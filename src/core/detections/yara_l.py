"""Google SecOps YARA-L draft generator.

The output is **draft / starter** YARA-L — emphatically not a finished
detection ready to deploy in Chronicle/SecOps. Field paths follow the
Unified Data Model (UDM) but specific dataset coverage and parser
choices vary by environment, so a generated rule will almost always
need tuning. The generator instead aims for "useful starter":

* Map the hint's Sigma ``logsource.category`` onto the closest UDM
  ``metadata.event_type`` (``PROCESS_LAUNCH`` / ``FILE_MODIFICATION`` /
  ``REGISTRY_MODIFICATION`` / ``PROCESS_OPEN`` / ``PROCESS_MODULE_LOAD`` /
  ``NETWORK_CONNECTION`` / ``NETWORK_DNS`` / ``GENERIC_EVENT``).
* Convert each Sigma ``selection`` ``field|modifier: value`` into a
  UDM event predicate (``$e.<udm_field> = /pattern/ nocase`` for
  contains / endswith / startswith, ``= "value"`` for exact, numeric
  comparison for numeric values, alternation regex for ``|in`` lists).
* Preserve the historical ``meta:`` block shape (``technique`` /
  ``run_id`` / ``generated_by`` / ``risk_score`` / ``risk_severity``)
  so callers that grep against that contract continue to work.
* Fall back to the historic substring-on-process-path shape when the
  hint carries no ``detection.selection`` block — keeps backwards
  compatibility for legacy callers and the existing
  ``test_yara_l_unspecified_run_id_falls_back_to_manual`` test.

The previous generator emitted the same two events lines regardless
of technique:

    $e.metadata.event_type = "PROCESS_LAUNCH"
    $e.target.process.file.full_path contains "<process_name>"

A YARA-L rule generated from a registry-poking technique still
matched on ``target.process.file.full_path``, which a defender
analyst would reject on review. The upgrade routes the per-technique
discriminator that the module already supplies through to a
field/value pair the SecOps engine can evaluate against UDM events.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Mapping, Tuple


# Sigma ``logsource.category`` -> UDM ``metadata.event_type``.
# The right-hand side names are the canonical UDM event types
# Chronicle/SecOps writes for each telemetry family. ``GENERIC_EVENT``
# is the documented fallback when no closer match exists.
_LOGSOURCE_CATEGORY_TO_EVENT_TYPE: Dict[str, str] = {
    "process_creation": "PROCESS_LAUNCH",
    "process_access": "PROCESS_OPEN",
    "file_event": "FILE_MODIFICATION",
    "registry_event": "REGISTRY_MODIFICATION",
    "image_load": "PROCESS_MODULE_LOAD",
    "network_connection": "NETWORK_CONNECTION",
    "dns": "NETWORK_DNS",
    "dns_query": "NETWORK_DNS",
    "threat_intelligence": "GENERIC_EVENT",
    "email": "EMAIL_TRANSACTION",
    # Auth-centric categories used by the initial_access vector
    # catalog (valid_accounts / domain_accounts / cloud_accounts /
    # trusted_relationship). USER_LOGIN is the documented Chronicle
    # UDM event_type for successful auth telemetry.
    "authentication": "USER_LOGIN",
    "cloud_audit": "USER_LOGIN",
    # Web/proxy categories used by initial_access
    # (exploit_public_app / drive_by_compromise).
    "webserver": "NETWORK_HTTP",
    "proxy": "NETWORK_HTTP",
    # Device-events for hardware_additions (USB device-class hits).
    "device_event": "RESOURCE_CREATION",
    # VoIP for spearphishing_voice. Chronicle has no canonical
    # voice/telephony event_type, so GENERIC_EVENT keeps the rule
    # buildable without claiming a specific UDM family.
    "voip": "GENERIC_EVENT",
}


# Sigma field name (with the ``|modifier`` suffix already stripped)
# -> UDM event field path. UDM nests every event under ``$e``; the
# value here is the dotted suffix appended to ``$e.``. Keys cover
# Sysmon-style Windows fields, the lowercase dotted forms BlueFire
# modules use directly, plus the network / file / service / email
# families used by the legacy adapter and tactic catalogs. Unknown
# fields fall back to :func:`_fallback_udm_for_category`, which
# picks a category-appropriate path so a NETWORK_CONNECTION rule
# does not silently end up matching on
# ``principal.process.command_line``.
_SIGMA_FIELD_TO_UDM: Dict[str, str] = {
    # Sysmon Windows fields
    "Image": "principal.process.file.full_path",
    "ImageLoaded": "target.process.file.full_path",
    "CommandLine": "principal.process.command_line",
    "ParentImage": "principal.process.parent_process.file.full_path",
    "ParentCommandLine": "principal.process.parent_process.command_line",
    "TargetFilename": "target.file.full_path",
    "TargetObject": "target.registry.registry_key",
    "CallTrace": "principal.process.api_calls",
    "EventID": "metadata.product_event_type",
    "EventCode": "metadata.product_event_type",
    "User": "principal.user.userid",
    # Process family (lowercase dotted form used by
    # credential_access / discovery / persistence / etc. catalogs)
    "process.command_line": "principal.process.command_line",
    "process.parent_command_line": "principal.process.parent_process.command_line",
    "process.api_call": "principal.process.api_calls",
    "process.name": "principal.process.file.full_path",
    "process.image": "principal.process.file.full_path",
    "process.parent.command_line": "principal.process.parent_process.command_line",
    # File family
    "file.path": "target.file.full_path",
    "file.entropy": "target.file.entropy",
    "file.attribute": "target.file.attribute",
    "file.attributes": "target.file.attribute",
    "file.action": "metadata.event_subtype",
    "file.operation": "metadata.event_subtype",
    "file.extension": "target.file.full_path",
    # Registry family
    "registry.key": "target.registry.registry_key",
    "registry.key.path": "target.registry.registry_key",
    # Service family
    "service.name": "target.resource.name",
    "service.image_path": "target.process.file.full_path",
    "service.action": "metadata.event_subtype",
    # Resource (catch-all)
    "resource.kind": "target.resource.resource_type",
    # Email family
    "email.recipient": "network.email.to",
    "email.subject": "network.email.subject",
    "email.url": "network.http.referral_url",
    "email.attachment.extension": "target.file.full_path",
    "email.sender.service": "principal.user.attribute.labels",
    # Auth family (used by initial_access valid_accounts variants
    # and by lateral_movement / credential_access auth telemetry).
    "event.action": "security_result.action",
    "event.logon_type": "extensions.auth.mechanism",
    "user.name": "target.user.userid",
    "user.domain": "target.user.windows_sid",
    "user.oauth_provider": "target.user.attribute.labels",
    # Telephony fallback.
    "call.callee.user": "target.user.userid",
    # HTTP / proxy family.
    "http.url": "target.url",
    "http.user_agent": "network.http.user_agent",
    "http.method": "network.http.method",
    # Device-event family (hardware_additions / removable_media).
    "device.class": "target.resource.resource_type",
    # Legacy lowercase form
    "target.process.name": "target.process.file.full_path",
    # Network family
    "network.transport": "network.application_protocol",
    "network.protocol": "network.application_protocol",
    "network.endpoint": "target.url",
    "network.url": "target.url",
    "network.dst_port": "target.port",
    "network.dst_country": "target.location.country_or_region",
    "network.dst_host": "target.hostname",
    "network.dst_ip": "target.ip",
    "network.target": "target.hostname",
    "network.tool": "principal.process.file.full_path",
    "network.banner_grab": "network.received_bytes",
    "network.payload_padding": "network.received_bytes",
    "network.encapsulation": "network.application_protocol",
    "network.hop_count": "network.network_hop_count",
    # DNS family
    "dns.question.name": "network.dns.questions.name",
    "dns.question.length": "network.dns.questions.name",
    "dns.record_type": "network.dns.questions.type",
    # TLS family
    "tls.sni": "network.tls.client.server_name",
    # Threat-intel family (BlueFire-internal field names)
    "threat.actor": "metadata.event_metadata.threat_actor",
    "threat.ttp_focus": "metadata.event_metadata.ttp",
    "threat.ioc_class": "metadata.event_metadata.ioc_class",
    "threat.cve_pattern": "vulnerability.cve_id",
    "threat.credential_corpus": "metadata.event_metadata.credential_corpus",
    "threat.domain_pattern": "network.dns.questions.name",
    "threat.network_pattern": "principal.ip",
}


# Category-aware fallback UDM field. When a selection key is absent
# from :data:`_SIGMA_FIELD_TO_UDM`, the generator picks a fallback
# tied to the rule's logsource category — a NETWORK_CONNECTION rule
# falls back to ``target.hostname``, a FILE_MODIFICATION rule falls
# back to ``target.file.full_path``, etc. Without this, every
# unmapped key landed under ``principal.process.command_line``,
# which is correct for PROCESS_LAUNCH events and nonsense
# everywhere else.
_CATEGORY_FALLBACK_UDM: Dict[str, str] = {
    "process_creation": "principal.process.command_line",
    "process_access": "principal.process.api_calls",
    "file_event": "target.file.full_path",
    "registry_event": "target.registry.registry_key",
    "image_load": "target.process.file.full_path",
    "network_connection": "target.hostname",
    "dns": "network.dns.questions.name",
    "dns_query": "network.dns.questions.name",
    "email": "network.email.to",
    "threat_intelligence": "metadata.event_metadata.threat_actor",
    # Auth: a USER_LOGIN rule with an unmapped key falls back to
    # ``target.user.userid`` rather than command_line.
    "authentication": "target.user.userid",
    "cloud_audit": "target.user.userid",
    # Web/proxy: HTTP rules fall back to the URL.
    "webserver": "target.url",
    "proxy": "target.url",
    # VoIP: telephony rules fall back to the called user.
    "voip": "target.user.userid",
    # Device events: fall back to the resource type.
    "device_event": "target.resource.resource_type",
}
_FALLBACK_UDM = "principal.process.command_line"
_FALLBACK_EVENT_TYPE = "GENERIC_EVENT"
# Reasonable upper bound on selection clauses surfaced in the events
# block. The Sigma side typically has 1-3, but a future rule could
# include more; cap so the YARA-L rule stays readable.
_MAX_SELECTION_CLAUSES = 8


def _udm_field(sigma_key: str, *, category: str = "") -> str:
    """Map a Sigma selection key (with optional ``|modifier``) to a UDM field path.

    When the bare field has no entry in :data:`_SIGMA_FIELD_TO_UDM`,
    fall back to a category-appropriate path (see
    :data:`_CATEGORY_FALLBACK_UDM`) so an unmapped field in a
    NETWORK_CONNECTION / FILE_MODIFICATION / REGISTRY_MODIFICATION
    rule does not silently land on ``principal.process.command_line``.
    """
    bare = sigma_key.split("|", 1)[0].strip()
    mapped = _SIGMA_FIELD_TO_UDM.get(bare)
    if mapped is not None:
        return mapped
    return _CATEGORY_FALLBACK_UDM.get(category, _FALLBACK_UDM)


def _modifier(sigma_key: str) -> str:
    return sigma_key.split("|", 1)[1].strip().lower() if "|" in sigma_key else ""


def _yaral_regex_literal(operator: str, value: str) -> str:
    """Return a YARA-L regex literal of the form ``/<pattern>/ nocase``.

    The value is escaped via :func:`re.escape` so user-supplied
    backslashes / dots / question marks become literal matches.
    Embedded ``/`` characters are also escaped so they do not
    terminate the regex literal.
    """
    escaped = re.escape(value).replace("/", r"\/")
    if operator == "contains":
        body = f".*{escaped}.*"
    elif operator == "endswith":
        body = f".*{escaped}$"
    elif operator == "startswith":
        body = f"^{escaped}.*"
    else:  # exact match expressed as anchored regex
        body = f"^{escaped}$"
    return f"/{body}/ nocase"


def _quote_string(value: str) -> str:
    """Return a YARA-L double-quoted string literal."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _selection_predicates(
    detection: Mapping[str, Any] | None, *, category: str = ""
) -> List[str]:
    """Render Sigma ``selection`` k/v pairs as YARA-L event predicates.

    Each predicate is an ``$e.<udm_field> <operator> <literal>``
    string. Returns at most :data:`_MAX_SELECTION_CLAUSES`
    predicates so the events block stays readable when a Sigma
    rule carries a wide selection map.

    ``category`` (Sigma logsource ``category``) selects a
    category-appropriate UDM fallback for any selection key absent
    from :data:`_SIGMA_FIELD_TO_UDM`.
    """
    if not isinstance(detection, Mapping):
        return []
    selection = detection.get("selection")
    if not isinstance(selection, Mapping):
        return []
    predicates: List[str] = []
    for raw_key, raw_value in selection.items():
        key = str(raw_key)
        udm = _udm_field(key, category=category)
        modifier = _modifier(key)

        # List handling depends on the Sigma modifier:
        #
        # * ``|in`` (exact list membership) -> anchored regex
        #   ``/^(a|b|c)$/`` so a value like ``A`` does not also
        #   match ``AAAA`` / ``ANY``.
        # * ``|contains_any`` (substring-OR) -> unanchored regex
        #   ``/(a|b|c)/`` so ``-enc`` matches inside a longer
        #   command line. This is the legacy_packs.py shipped use
        #   case for ``process.command_line|contains_any:
        #   ["-enc", "-nop"]``; anchoring would make the rule
        #   unsatisfiable when paired with a sibling
        #   ``|contains: "powershell"`` predicate.
        # * ``|contains_all`` (substring-AND) -> separate predicate
        #   per value (each substring must appear), capped against
        #   ``_MAX_SELECTION_CLAUSES``.
        # * No modifier with a list -> default to ``|in``-style
        #   exact membership, since YAML authors who mean
        #   "any of these" usually pick ``|in`` or
        #   ``|contains_any`` explicitly.
        if isinstance(raw_value, (list, tuple)) and raw_value:
            if modifier == "contains_any":
                joined = "|".join(
                    re.escape(str(v)).replace("/", r"\/") for v in raw_value
                )
                predicates.append(f"$e.{udm} = /({joined})/ nocase")
            elif modifier == "contains_all":
                for value in raw_value:
                    if len(predicates) >= _MAX_SELECTION_CLAUSES:
                        break
                    predicates.append(
                        f"$e.{udm} = "
                        f"{_yaral_regex_literal('contains', str(value))}"
                    )
            else:
                # ``|in`` or no modifier -> anchored exact membership.
                joined = "|".join(
                    re.escape(str(v)).replace("/", r"\/") for v in raw_value
                )
                predicates.append(f"$e.{udm} = /^({joined})$/ nocase")
        elif isinstance(raw_value, bool):
            # Bools land as numeric 0/1 in UDM-like predicates.
            predicates.append(f"$e.{udm} = {1 if raw_value else 0}")
        elif isinstance(raw_value, (int, float)) and not modifier:
            predicates.append(f"$e.{udm} = {raw_value}")
        else:
            value_str = str(raw_value)
            if modifier in ("contains", "endswith", "startswith"):
                predicates.append(
                    f"$e.{udm} = {_yaral_regex_literal(modifier, value_str)}"
                )
            elif modifier == "contains_any":
                # Single-value ``|contains_any`` collapses to substring match.
                predicates.append(
                    f"$e.{udm} = {_yaral_regex_literal('contains', value_str)}"
                )
            elif modifier == "in":
                # Single-value ``|in`` collapses to exact match.
                predicates.append(f"$e.{udm} = {_quote_string(value_str)}")
            else:
                predicates.append(f"$e.{udm} = {_quote_string(value_str)}")
        if len(predicates) >= _MAX_SELECTION_CLAUSES:
            break
    return predicates


def _resolve_event_type(hint: Mapping[str, Any]) -> Tuple[str, str, str]:
    """Resolve a ``(event_type, product, category)`` tuple from the hint.

    Falls back to the historic ``PROCESS_LAUNCH`` event type only
    when the explicit ``event_type`` hint is set; otherwise the
    documented UDM ``GENERIC_EVENT`` is returned. Callers can branch
    on ``category == ""`` to detect "no logsource block at all".
    """
    explicit_event_type = str(hint.get("event_type") or "").strip()
    logsource = hint.get("logsource") if isinstance(hint, Mapping) else None
    product = ""
    category = ""
    if isinstance(logsource, Mapping):
        product = str(logsource.get("product") or "").strip().lower()
        category = str(logsource.get("category") or "").strip().lower()
    if explicit_event_type:
        return explicit_event_type, product, category
    if category:
        return (
            _LOGSOURCE_CATEGORY_TO_EVENT_TYPE.get(category, _FALLBACK_EVENT_TYPE),
            product,
            category,
        )
    # No logsource and no explicit event_type — preserve the
    # historic ``PROCESS_LAUNCH`` to keep the legacy fallback
    # rule shape stable for callers that exercised the old path.
    return "PROCESS_LAUNCH", product, category


def build_yara_l_rule(run_id: str, module: str, hint: Dict[str, Any]) -> str:
    """Render a YARA-L rule string for one detection hint.

    The ``meta:`` block carries ``technique`` / ``run_id`` /
    ``generated_by`` / ``risk_score`` / ``risk_severity`` — the
    contract every existing test pins. The ``events:`` block now
    derives from the Sigma ``logsource`` + ``detection.selection``
    in the hint when present, falling back to the historic
    substring-on-process-path predicate otherwise.
    """
    technique_id = (
        hint.get("mitre_technique_id") or hint.get("mitre_technique") or "T0000"
    )
    risk_score = int(hint.get("risk_score", 50))
    risk_score = max(0, min(100, risk_score))
    risk_severity = str(hint.get("risk_severity", "medium")).lower()
    if risk_severity not in {"low", "medium", "high", "critical"}:
        risk_severity = "medium"

    event_type, product, category = _resolve_event_type(hint)
    detection = hint.get("detection") if isinstance(hint, Mapping) else None
    predicates = _selection_predicates(detection, category=category)

    safe_name = f"{module}_{run_id}".replace("-", "_").replace(":", "_")
    rule_id = f"bluefire_{safe_name}_{technique_id.replace('.', '_').replace('-', '_')}"

    lines: List[str] = [
        f"rule {rule_id} {{",
        "  meta:",
        f"    technique = \"{technique_id}\"",
        f"    run_id = \"{run_id}\"",
        "    generated_by = \"BlueFire-Nexus\"",
        f"    risk_score = \"{risk_score}\"",
        f"    risk_severity = \"{risk_severity}\"",
    ]
    if product:
        lines.append(f"    logsource_product = \"{product}\"")
    if category:
        lines.append(f"    logsource_category = \"{category}\"")
    lines.append("  events:")
    lines.append(f"    $e.metadata.event_type = \"{event_type}\"")
    if predicates:
        for predicate in predicates:
            lines.append(f"    {predicate}")
    else:
        # Legacy fallback: substring-on-process-path against the
        # most useful identifier we have. Preserves the historic
        # test contract for callers that pass no Sigma selection.
        legacy_value = (
            hint.get("process_name")
            or hint.get("process_command_line")
            or hint.get("network_url")
            or hint.get("endpoint")
            or module
        )
        lines.append(
            f"    $e.target.process.file.full_path = "
            f"{_yaral_regex_literal('contains', str(legacy_value))}"
        )
    lines.append("  condition:")
    lines.append("    $e")
    lines.append("}")
    return "\n".join(lines) + "\n"


def generate_yara_l(
    name: str,
    technique_id: str,
    metadata: Dict[str, Any],
    *,
    run_id: str = "manual",
) -> str:
    """Render a YARA-L rule for a single detection hint.

    The earlier signature hardcoded ``run_id="manual"`` for the
    detection engine's call site, leaving every generated YARA-L
    rule with a stale ``meta.run_id = "manual"`` even when the
    Sigma rule next to it carried the real run id. The keyword-
    only ``run_id`` parameter restores parity with the Sigma path
    while keeping older callers (``run_id`` defaults to
    ``"manual"`` to preserve the historical behaviour for any
    out-of-tree caller that does not pass one).
    """
    hint: Dict[str, Any] = dict(metadata or {})
    hint.setdefault("mitre_technique_id", technique_id or "T0000")
    return build_yara_l_rule(run_id, name, hint)
