"""Splunk SPL detection draft generator.

The output is **draft / starter** SPL — emphatically not a
finished detection ready to deploy. Splunk environments differ
enough (index naming, sourcetype routing, field extractions)
that a single generated query cannot be correct everywhere. The
generator instead aims for "useful starter": map the hint's
Sigma logsource onto the most common Splunk sourcetypes for
that telemetry family, translate Sigma selection fields into
Splunk Common Information Model (CIM) field names so the rule
is portable across CIM-normalised sourcetypes, surface a CIM
datamodel hint so operators can swap the search to ``tstats
from datamodel=...`` for accelerated environments, and emit
run-attribution ``eval`` fields so the search remains traceable
to the run that produced it. A leading comment header makes the
draft status explicit so the operator knows to adjust
``index=`` / ``sourcetype=`` for their environment before
deploying.

The earlier generator emitted only ``| makeresults | eval ...``,
which round-tripped the run metadata but never touched any
data source — useful as a self-test, not as a detection. The
``| makeresults`` form is preserved as a fallback when the hint
carries no logsource information (e.g. legacy capability runs
that bypass the Sigma logsource block) so existing tooling that
ingested the metadata-echo shape keeps working.

The intermediate generator (PR #112 era) used the raw Sigma
field name as the SPL ``where`` field, e.g.
``| where Image="*powershell.exe"``. That fired only on raw
Sysmon EventCode=1 events, not on CIM-normalised Endpoint
sourcetypes (CrowdStrike Falcon, Carbon Black, defender-for-
endpoint, Sysmon-after-CIM-extractions, etc.). The current
generator translates Sigma field names through
:data:`_SIGMA_FIELD_TO_CIM` so the same rule fires across every
CIM-normalised Endpoint sourcetype. Unmapped Sigma fields
(threat-intel, telephony, BlueFire-internal artefact fields)
fall through to the verbatim Sigma field name so the rule is
still syntactically valid and an operator can manually rename
them.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, List, Mapping, Tuple

from ..models import ModuleResult


def _quote(value: str) -> str:
    return value.replace('"', '\\"')


# Mapping from Sigma-style ``logsource`` (product / category) onto
# the most common Splunk sourcetype hint for that family. The
# tuples are ``(sourcetype_clause, eventcode_clause)`` — both are
# already valid SPL fragments so the renderer just inlines them.
# Empty strings mean "no hint we can stand behind"; the renderer
# falls back to ``sourcetype=*`` plus a comment for the operator
# to fill in.
_LOGSOURCE_TO_SPL: dict[Tuple[str, str], Tuple[str, str]] = {
    # ---- Process family ----
    ("windows", "process_creation"): (
        '(sourcetype="WinEventLog:Security" OR sourcetype="Sysmon" '
        'OR sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational")',
        "(EventCode=4688 OR EventCode=1)",
    ),
    ("linux", "process_creation"): (
        '(sourcetype="linux_audit" OR sourcetype="auditd")',
        "type=EXECVE",
    ),
    ("macos", "process_creation"): (
        '(sourcetype="osquery:results" OR sourcetype="osquery:processes")',
        "",
    ),
    ("host", "process_creation"): (
        '(sourcetype="WinEventLog:Security" OR sourcetype="Sysmon" '
        'OR sourcetype="linux_audit")',
        "",
    ),
    ("windows", "process_access"): (
        '(sourcetype="Sysmon" OR '
        'sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational")',
        "EventCode=10",
    ),
    ("windows", "image_load"): (
        '(sourcetype="Sysmon" OR '
        'sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational")',
        "EventCode=7",
    ),
    # ---- Service family ----
    ("windows", "service_creation"): (
        '(sourcetype="WinEventLog:System" OR sourcetype="WinEventLog:Security")',
        "EventCode=7045",
    ),
    ("windows", "service_modification"): (
        '(sourcetype="WinEventLog:System" OR sourcetype="WinEventLog:Security")',
        "(EventCode=7040 OR EventCode=4697)",
    ),
    # ---- Network family ----
    ("windows", "network_connection"): (
        '(sourcetype="Sysmon" OR '
        'sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational")',
        "EventCode=3",
    ),
    ("linux", "network_connection"): (
        '(sourcetype="linux_audit" OR sourcetype="auditd")',
        "",
    ),
    ("host", "network_connection"): (
        '(sourcetype="Sysmon" OR sourcetype="linux_audit" OR sourcetype="stream:tcp")',
        "",
    ),
    # ---- DNS family ----
    ("windows", "dns_query"): (
        '(sourcetype="Sysmon" OR '
        'sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational")',
        "EventCode=22",
    ),
    ("dns", "dns_query"): (
        '(sourcetype="stream:dns" OR sourcetype="dns")',
        "",
    ),
    # ``logsource: { category: dns, product: network }`` is the
    # exfiltration / command_control DNS-family default; map it to
    # the same sourcetype family as ``(dns, dns_query)``.
    ("network", "dns"): (
        '(sourcetype="stream:dns" OR sourcetype="dns")',
        "",
    ),
    ("dns", "dns"): (
        '(sourcetype="stream:dns" OR sourcetype="dns")',
        "",
    ),
    # ---- File family ----
    ("windows", "file_event"): (
        '(sourcetype="Sysmon" OR '
        'sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational")',
        "(EventCode=11 OR EventCode=2)",
    ),
    ("linux", "file_event"): (
        '(sourcetype="linux_audit" OR sourcetype="auditd")',
        "(type=PATH OR type=CREATE)",
    ),
    ("macos", "file_event"): (
        '(sourcetype="osquery:results" OR sourcetype="osquery:fim")',
        "",
    ),
    ("host", "file_event"): (
        '(sourcetype="Sysmon" OR sourcetype="linux_audit" OR sourcetype="osquery:fim")',
        "",
    ),
    # ---- Registry family ----
    ("windows", "registry_event"): (
        '(sourcetype="Sysmon" OR '
        'sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational")',
        "(EventCode=12 OR EventCode=13 OR EventCode=14)",
    ),
    # ---- Auth family ----
    ("windows", "authentication"): (
        'sourcetype="WinEventLog:Security"',
        "(EventCode=4624 OR EventCode=4625 OR EventCode=4648)",
    ),
    ("linux", "authentication"): (
        '(sourcetype="linux_secure" OR sourcetype="auditd")',
        "(type=USER_AUTH OR type=USER_LOGIN)",
    ),
    ("generic", "authentication"): (
        '(sourcetype="WinEventLog:Security" OR sourcetype="linux_secure" '
        'OR sourcetype="auditd")',
        "",
    ),
    ("host", "authentication"): (
        '(sourcetype="WinEventLog:Security" OR sourcetype="linux_secure")',
        "",
    ),
    # ---- Cloud audit family ----
    ("generic", "cloud_audit"): (
        '(sourcetype="aws:cloudtrail" OR sourcetype="google:gcp:audit" '
        'OR sourcetype="azure:audit")',
        "",
    ),
    # ---- Web / proxy family ----
    ("generic", "webserver"): (
        '(sourcetype="access_combined" OR sourcetype="apache:access" '
        'OR sourcetype="iis")',
        "",
    ),
    ("generic", "proxy"): (
        '(sourcetype="stream:http" OR sourcetype="proxy" OR sourcetype="bluecoat")',
        "",
    ),
    # ---- Email family ----
    ("generic", "email"): (
        '(sourcetype="ms:o365:reporting:messagetrace" OR sourcetype="email" '
        'OR sourcetype="exchange:message_tracking")',
        "",
    ),
    ("host", "email"): (
        '(sourcetype="ms:o365:reporting:messagetrace" OR sourcetype="email")',
        "",
    ),
    # ---- Device family (USB / hardware additions) ----
    ("windows", "device_event"): (
        'sourcetype="WinEventLog:System"',
        "(EventCode=20001 OR EventCode=20003 OR EventCode=24576)",
    ),
    # ---- Threat-intel family. No host-side telemetry; the closest
    # Splunk story is the standard threat-intel sourcetypes that
    # operators ingest from CTI feeds (Splunk Enterprise Security
    # threatlists, OpenCTI / MISP exports, passive-DNS feeds, etc.).
    # Mapping to those keeps the rule syntactically valid and routes
    # the operator toward the correct telemetry instead of the
    # metadata-echo / placeholder-sourcetype fallback. ----
    ("vendor", "threat_intelligence"): (
        '(sourcetype="threatlist" OR sourcetype="cim:threatintel")',
        "",
    ),
    ("generic", "threat_intelligence"): (
        '(sourcetype="threatlist" OR sourcetype="cim:threatintel")',
        "",
    ),
    ("ioc_feed", "threat_intelligence"): (
        '(sourcetype="threatlist" OR sourcetype="cim:threatintel")',
        "",
    ),
    ("leak_feed", "threat_intelligence"): (
        '(sourcetype="threatlist" OR sourcetype="cim:threatintel")',
        "",
    ),
    ("vuln_feed", "threat_intelligence"): (
        '(sourcetype="threatlist" OR sourcetype="cim:threatintel")',
        "",
    ),
    ("passive_dns", "threat_intelligence"): (
        '(sourcetype="passive_dns" OR sourcetype="threatlist")',
        "",
    ),
    ("asn_feed", "threat_intelligence"): (
        '(sourcetype="cim:threatintel" OR sourcetype="bgp:asn")',
        "",
    ),
    # ---- Resource-development pre-foothold families. The
    # ``resource_development`` tactic represents attacker planning
    # (domain registration / VPS provisioning / cert acquisition /
    # compromised infrastructure / SaaS account provisioning /
    # marketplace tool acquisition). There is no canonical host-
    # side Splunk sourcetype for "attacker registered a domain";
    # the closest defensive telemetry is the threat-intel family
    # plus passive-DNS / certificate-transparency / marketplace
    # leak feeds. Mapping these pairs keeps generated SPL searches
    # rooted in a real sourcetype an operator could ingest, and
    # the leading DRAFT header reminds them to swap the index/
    # sourcetype for whatever feed their environment actually
    # carries. ----
    ("registrar", "infrastructure_provisioning"): (
        '(sourcetype="passive_dns" OR sourcetype="threatlist" '
        'OR sourcetype="cim:threatintel")',
        "",
    ),
    ("cloud", "infrastructure_provisioning"): (
        '(sourcetype="aws:cloudtrail" OR sourcetype="google:gcp:audit" '
        'OR sourcetype="azure:audit")',
        "",
    ),
    ("saas", "infrastructure_provisioning"): (
        '(sourcetype="cim:threatintel" OR sourcetype="ms:o365:management")',
        "",
    ),
    ("compromised", "infrastructure_provisioning"): (
        '(sourcetype="threatlist" OR sourcetype="passive_dns" '
        'OR sourcetype="cim:threatintel")',
        "",
    ),
    ("saas", "account_provisioning"): (
        '(sourcetype="ms:o365:management" OR sourcetype="cim:threatintel")',
        "",
    ),
    ("ca", "certificate_acquisition"): (
        '(sourcetype="cert_transparency" OR sourcetype="cim:certificate" '
        'OR sourcetype="threatlist")',
        "",
    ),
    ("marketplace", "tooling_acquisition"): (
        '(sourcetype="threatlist" OR sourcetype="cim:threatintel")',
        "",
    ),
    # ---- Legacy-wrapped (PR #105). ``logsource: legacy_wrapped/bluefire``
    # explicitly does not have a real Splunk sourcetype; emit a clearly-
    # placeholder filter so the rule still parses but the operator sees
    # the placeholder and replaces it. ----
    ("bluefire", "legacy_wrapped"): (
        'sourcetype="bluefire:legacy_wrapped"',
        "",
    ),
}


# Sigma field name (with the ``|modifier`` suffix already stripped) ->
# Splunk Common Information Model (CIM) field name. CIM is the canonical
# field-normalisation layer used by Splunk Enterprise Security, Splunk
# SOAR, and virtually every commercial Splunk app. Translating Sigma
# field names into CIM lets the same generated SPL fire across every
# CIM-normalised Endpoint / Network / Web / Auth sourcetype instead of
# only the raw Sysmon / EVTX shape. Field names below match Splunk CIM
# 5.x canonical names. Where no canonical CIM field exists for a Sigma
# field (telephony, threat-intel internals, BlueFire artefact-only
# fields), the entry is omitted and the renderer falls back to the
# verbatim Sigma field name so the clause is still syntactically valid.
_SIGMA_FIELD_TO_CIM: dict[str, str] = {
    # ---- Endpoint.Processes ----
    "Image": "process_path",
    "CommandLine": "process",
    "ParentImage": "parent_process_path",
    "ParentCommandLine": "parent_process",
    "User": "user",
    "process.image": "process_path",
    "process.name": "process_name",
    "process.command_line": "process",
    "process.parent_command_line": "parent_process",
    "process.parent.command_line": "parent_process",
    "target.process.name": "process_name",
    # ``ImageLoaded`` (Sysmon EventCode=7 / image_load) names the
    # loaded module path, not the executing process path. CIM's
    # ``process_path`` represents the EXECUTING process executable —
    # mapping ``ImageLoaded`` onto it would silently turn an
    # image-load detection into an executable-name match and miss
    # the intended events. CIM has no canonical "loaded module"
    # field, so leave ``ImageLoaded`` unmapped — the renderer falls
    # through to the verbatim Sigma field name, which is exactly
    # what CIM-after-Sysmon extractions preserve anyway.
    # ---- Endpoint.Filesystem ----
    "TargetFilename": "file_path",
    "file.path": "file_path",
    "file.name": "file_name",
    # ``file.extension`` carries just the suffix (``.locked``,
    # ``.enc``, ``.crypt``); CIM's canonical field for that is
    # ``file_extension`` (Endpoint.Filesystem 5.x). Mapping it onto
    # ``file_name`` would turn extension-equality / extension-IN
    # selections into full-name equality checks that almost never
    # match a real filename — false negatives across the impact
    # data_encryption profile and any downstream rule using
    # ``file.extension|in``.
    "file.extension": "file_extension",
    "file.action": "action",
    "file.operation": "action",
    # ---- Endpoint.Registry ----
    "TargetObject": "registry_path",
    "registry.key": "registry_path",
    "registry.key.path": "registry_path",
    # ---- Endpoint.Services ----
    "service.name": "service",
    # ``service.image_path`` is the full path to the service binary —
    # CIM Endpoint.Services 5.x canonical field is ``service_path``.
    # The earlier draft mapped onto Endpoint.Filesystem's ``file_path``,
    # routing the rule to the wrong datamodel. ``service_path`` keeps
    # the rule under Endpoint.Services where service-create / -modify
    # detections belong.
    "service.image_path": "service_path",
    "service.action": "action",
    # ---- Authentication.Authentication ----
    "user.name": "user",
    "user.domain": "dest_nt_domain",
    "user.windows_domain": "dest_nt_domain",
    # ``user.windows_sid`` carries SID strings (``S-1-5-21-...``),
    # not usernames. CIM Authentication has no canonical SID-only
    # field; mapping onto ``user`` (a username field) silently
    # widens the search to match SIDs against username extractions.
    # Leave unmapped — verbatim pass-through is honest and lets the
    # operator choose the correct field for their environment.
    "event.action": "action",
    # ---- Network_Traffic.All_Traffic ----
    "network.dst_port": "dest_port",
    "network.dst_host": "dest",
    "network.dst_hostname": "dest",
    "network.dst_ip": "dest_ip",
    "network.dst_country": "dest_country",
    "network.target": "dest",
    "network.transport": "transport",
    # The standard / legacy module catalogs use ``network.protocol``
    # for transport / link-layer values like ``"icmp"``, ``"quic"``,
    # ``"bluetooth"`` — not application-layer labels. CIM
    # Network_Traffic ``app`` is reserved for application protocol
    # labels (``http`` / ``ftp`` / ``smtp``), so map ``network.protocol``
    # onto CIM ``transport`` to match the values BlueFire actually emits.
    "network.protocol": "transport",
    "network.url": "url",
    "network.encapsulation": "transport",
    # ---- Network_Resolution.DNS ----
    "dns.question.name": "query",
    "dns.record_type": "record_type",
    # ---- Web.Web ----
    "http.url": "url",
    "http.user_agent": "http_user_agent",
    "http.method": "http_method",
    # ---- Email.All_Email ----
    "email.recipient": "recipient",
    "email.subject": "subject",
    "email.url": "url",
    "email.attachment.extension": "file_name",
    "email.sender.service": "src_user",
    # ---- Threat_Intelligence ----
    "threat.actor": "threat_group",
    "threat.ttp_focus": "threat_category",
    "threat.ioc_class": "ioc_type",
    "threat.cve_pattern": "cve",
    "threat.domain_pattern": "domain",
    "threat.network_pattern": "src",
}


# Sigma logsource (product, category) -> Splunk CIM datamodel hint.
# Surfaced as a comment line in the rendered SPL so an operator can
# choose to swap the ``index=*`` / ``where``-style search for a faster
# ``| tstats summariesonly=t count from datamodel=<datamodel>`` form
# in a CIM-accelerated environment. The rendered ``where`` search keeps
# working in unaccelerated environments where a datamodel isn't built.
_LOGSOURCE_TO_DATAMODEL: dict[Tuple[str, str], str] = {
    ("windows", "process_creation"): "Endpoint.Processes",
    ("linux", "process_creation"): "Endpoint.Processes",
    ("macos", "process_creation"): "Endpoint.Processes",
    ("host", "process_creation"): "Endpoint.Processes",
    ("windows", "process_access"): "Endpoint.Processes",
    ("windows", "image_load"): "Endpoint.Processes",
    ("windows", "service_creation"): "Endpoint.Services",
    ("windows", "service_modification"): "Endpoint.Services",
    ("windows", "network_connection"): "Network_Traffic.All_Traffic",
    ("linux", "network_connection"): "Network_Traffic.All_Traffic",
    ("host", "network_connection"): "Network_Traffic.All_Traffic",
    ("windows", "dns_query"): "Network_Resolution.DNS",
    ("dns", "dns_query"): "Network_Resolution.DNS",
    ("network", "dns"): "Network_Resolution.DNS",
    ("dns", "dns"): "Network_Resolution.DNS",
    ("windows", "file_event"): "Endpoint.Filesystem",
    ("linux", "file_event"): "Endpoint.Filesystem",
    ("macos", "file_event"): "Endpoint.Filesystem",
    ("host", "file_event"): "Endpoint.Filesystem",
    ("windows", "registry_event"): "Endpoint.Registry",
    ("windows", "authentication"): "Authentication.Authentication",
    ("linux", "authentication"): "Authentication.Authentication",
    ("generic", "authentication"): "Authentication.Authentication",
    ("host", "authentication"): "Authentication.Authentication",
    ("generic", "cloud_audit"): "Change.All_Changes",
    ("generic", "webserver"): "Web.Web",
    ("generic", "proxy"): "Web.Web",
    ("generic", "email"): "Email.All_Email",
    ("host", "email"): "Email.All_Email",
}


# CIM fields that carry numeric values. The renderer emits these as
# unquoted SPL predicates (``dest_port=443``) instead of the default
# string-literal form (``dest_port="443"``) so Splunk's numeric range
# filters (``dest_port>1024``, ``dest_port IN (80, 443)``) work
# downstream. Quoting a numeric field works for equality on most
# extractions but breaks numeric comparison and `tstats` accelerated
# searches that expect numeric type.
_CIM_NUMERIC_FIELDS: frozenset[str] = frozenset({"dest_port", "src_port"})


def _legacy_fields(hints: Mapping[str, Any], artifacts: Mapping[str, Any]) -> dict[str, str]:
    legacy = artifacts.get("legacy")
    payload = legacy.get("payload", {}) if isinstance(legacy, Mapping) else {}
    fields: dict[str, str] = {}
    for key in (
        "protocol",
        "transport",
        "endpoint",
        "command",
        "target_process",
        "campaign_id",
        "actor",
        "tactic",
        "technique",
        "mode",
        "capability",
        "legacy_subtype",
        "dns_record_type",
        "chunk_size",
        "rotation_count",
        "udp_port",
        "rpc_method",
        "api_hash",
        "runtime_warning",
    ):
        value = payload.get(key) if isinstance(payload, Mapping) else None
        if value is None:
            value = hints.get(key)
        if value is not None:
            fields[key] = str(value)
    risk_score = hints.get("risk_score")
    if risk_score is not None:
        fields["risk_score"] = str(risk_score)
    risk_severity = hints.get("risk_severity")
    if risk_severity is not None:
        fields["risk_severity"] = str(risk_severity)
    return fields


def _logsource_hint(hints: Mapping[str, Any]) -> Tuple[str, str, str, str]:
    """Resolve a ``(product, category, sourcetype_clause, eventcode_clause)``.

    Returns empty strings when the hint has no logsource block, so
    the caller can branch into the metadata-echo fallback shape.
    """
    logsource = hints.get("logsource") if isinstance(hints, Mapping) else None
    if not isinstance(logsource, Mapping):
        return "", "", "", ""
    product = str(logsource.get("product") or "").strip().lower()
    category = str(logsource.get("category") or "").strip().lower()
    sourcetype, eventcode = _LOGSOURCE_TO_SPL.get((product, category), ("", ""))
    return product, category, sourcetype, eventcode


def _datamodel_for(product: str, category: str) -> str:
    """Return the Splunk CIM datamodel hint for a logsource pair.

    Empty string means "no canonical CIM datamodel for this telemetry
    family"; the renderer suppresses the hint comment in that case so
    the operator isn't pointed at a non-existent datamodel.
    """
    return _LOGSOURCE_TO_DATAMODEL.get((product, category), "")


def _is_numeric_value(value: Any) -> bool:
    """Return ``True`` when ``value`` is a clean numeric (int / digit-only str).

    Floats are excluded so we don't accidentally drop quotes on values
    like a version string ``"1.0"`` (which Python parses as float
    elsewhere but Sigma authors write as plain strings). Negative
    integers and digit-only strings are accepted; the all-digit check
    keeps legitimate string values like ``"443/tcp"`` quoted.
    """
    if isinstance(value, bool):
        # bool is a subclass of int — reject explicitly so True/False
        # do not silently round-trip as 1 / 0.
        return False
    if isinstance(value, int):
        return True
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return False
        if stripped.startswith("-"):
            stripped = stripped[1:]
        return stripped.isdigit()
    return False


def _cim_field(field: str) -> str:
    """Map a bare Sigma field name onto the canonical CIM field name.

    Falls back to the verbatim Sigma field name when the field has no
    CIM equivalent — keeps the rule syntactically valid and lets the
    operator manually rename. The fallback intentionally does not pick
    a category-keyed default (unlike the YARA-L renderer) because SPL
    accepts any field name in a ``where`` clause; emitting an
    inappropriate CIM default would silently mask the unmapped field.
    """
    return _SIGMA_FIELD_TO_CIM.get(field, field)


def _selection_clauses(detection: Mapping[str, Any] | None) -> List[str]:
    """Render the Sigma ``selection`` block as SPL ``where`` clauses.

    Each Sigma ``field|modifier: value`` becomes a best-effort SPL
    predicate against the corresponding **Splunk CIM** field name
    (see :data:`_SIGMA_FIELD_TO_CIM`). Modifiers ``contains`` /
    ``startswith`` / ``endswith`` are honoured; unknown modifiers
    fall back to plain equality. Lists become ``IN (...)`` clauses.
    Numeric CIM fields (see :data:`_CIM_NUMERIC_FIELDS`) emit
    unquoted predicates so Splunk's numeric range / ``tstats``
    semantics keep working downstream. Returns a list of
    ``where``-style strings the caller can join.
    """
    if not isinstance(detection, Mapping):
        return []
    selection = detection.get("selection") if isinstance(detection, Mapping) else None
    if not isinstance(selection, Mapping):
        return []
    clauses: List[str] = []
    for raw_key, raw_value in selection.items():
        key = str(raw_key)
        modifier = ""
        if "|" in key:
            sigma_field, modifier = key.split("|", 1)
            sigma_field = sigma_field.strip()
            modifier = modifier.strip().lower()
        else:
            sigma_field = key.strip()
        if not sigma_field:
            continue
        field = _cim_field(sigma_field)
        is_numeric_field = field in _CIM_NUMERIC_FIELDS
        # Lists become IN (...) clauses — Splunk-friendly form. Numeric
        # CIM fields emit an unquoted IN (1, 2, 3) form.
        if isinstance(raw_value, (list, tuple)):
            if is_numeric_field and all(_is_numeric_value(v) for v in raw_value):
                rendered = ", ".join(str(v).strip() for v in raw_value)
            else:
                rendered = ", ".join(f'"{_quote(str(v))}"' for v in raw_value)
            clauses.append(f"{field} IN ({rendered})")
            continue
        # Numeric CIM fields with numeric scalars: drop the quotes so
        # downstream comparison / tstats acceleration keeps working.
        if is_numeric_field and _is_numeric_value(raw_value) and not modifier:
            clauses.append(f"{field}={str(raw_value).strip()}")
            continue
        value = _quote(str(raw_value))
        if modifier == "contains":
            clauses.append(f'{field}="*{value}*"')
        elif modifier == "startswith":
            clauses.append(f'{field}="{value}*"')
        elif modifier == "endswith":
            clauses.append(f'{field}="*{value}"')
        else:
            clauses.append(f'{field}="{value}"')
    return clauses


def _draft_header(
    *,
    run_id: str,
    module: str,
    technique: str,
    product: str,
    category: str,
    datamodel: str = "",
) -> str:
    """Multi-line backtick comment block flagging this as a draft.

    When ``datamodel`` is supplied (non-empty), an additional comment
    line surfaces the Splunk CIM datamodel hint so an operator can
    swap the rendered ``where``-style search for an accelerated
    ``| tstats summariesonly=t count from datamodel=<datamodel>``
    form.
    """
    lines: List[str] = [
        "` -- DRAFT detection search auto-generated by BlueFire-Nexus. -- `",
        "` -- Adjust index= / sourcetype= for your environment before deploying. -- `",
        f"` -- Module: {module} -- `",
        f"` -- Technique: {technique} -- `",
        f"` -- Run: {run_id} -- `",
    ]
    if product or category:
        lines.append(
            f"` -- Logsource: {product or '(any)'} / {category or '(any)'} -- `"
        )
    if datamodel:
        lines.append(
            f"` -- CIM datamodel hint: {datamodel} "
            "(swap to `| tstats summariesonly=t count from datamodel=...` "
            "for accelerated environments) -- `"
        )
    return "\n".join(lines)


def render_spl(
    result: ModuleResult,
    run_id: str,
    hint_override: Mapping[str, Any] | None = None,
) -> str:
    technique = result.techniques[0] if result.techniques else "T0000"
    module = result.module
    hints = hint_override or result.detection_hints or {}
    fields = _legacy_fields(hints, result.artifacts or {})
    detection = hints.get("detection") if isinstance(hints, Mapping) else None

    eval_parts = [
        f'run_id="{_quote(run_id)}"',
        f'module="{_quote(module)}"',
        f'technique="{_quote(technique)}"',
    ]
    for key, value in fields.items():
        eval_parts.append(f'{key}="{_quote(value)}"')

    product, category, sourcetype, eventcode = _logsource_hint(hints)
    datamodel = _datamodel_for(product, category)
    selection_clauses = _selection_clauses(detection)

    if not sourcetype and not selection_clauses:
        # Fallback: legacy metadata-echo shape. Existing tooling
        # that consumed the prior ``| makeresults | eval ...``
        # form keeps working when the hint has no logsource block
        # AND no usable selection. The leading header still makes
        # the draft status explicit.
        header = _draft_header(
            run_id=run_id,
            module=module,
            technique=technique,
            product=product,
            category=category,
            datamodel=datamodel,
        )
        table_fields = ["run_id", "module", "technique", *fields.keys()]
        body = (
            "| makeresults | eval "
            + ", ".join(eval_parts)
            + ' | where module!="" | table '
            + " ".join(table_fields)
        )
        return f"{header}\n{body}\n"

    # Normal path: real-feeling starter search rooted in actual
    # Splunk telemetry sourcetypes, refined by the Sigma selection
    # block, and tagged with run-attribution eval fields.
    header = _draft_header(
        run_id=run_id,
        module=module,
        technique=technique,
        product=product,
        category=category,
        datamodel=datamodel,
    )
    lines: List[str] = [header]
    if sourcetype:
        index_line = f"index=* {sourcetype}"
        if eventcode:
            index_line = f"{index_line} {eventcode}"
        lines.append(index_line)
    else:
        lines.append("index=* sourcetype=*")
        lines.append(
            "` -- No logsource hint available; pin sourcetype/index to your environment. -- `"
        )

    if selection_clauses:
        lines.append(
            "` -- Selection (Splunk CIM field names; adjust for non-CIM environments): -- `"
        )
        for clause in selection_clauses:
            lines.append(f"| where {clause}")

    # Run-attribution evals — same shape the legacy renderer
    # produced so existing tooling that greps for ``risk_score="``
    # / ``legacy_subtype="`` continues to find them.
    lines.append(f"| eval {', '.join(eval_parts)}")
    lines.append(
        '| stats count by host, source, sourcetype, run_id, module, technique'
    )
    return "\n".join(lines) + "\n"


def write_spl(result: ModuleResult, output_dir: Path, run_id: str) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    target = output_dir / f"{result.module}.spl"
    target.write_text(render_spl(result, run_id), encoding="utf-8")
    return target
