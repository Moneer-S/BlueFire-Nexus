"""Generate Sigma detection drafts from module outputs.

The Sigma ``fields:`` block exists so an alert reviewer (or a SIEM
that auto-pivots on Sigma metadata) sees the per-event columns that
are actually relevant to the rule's logsource. A ``file_event`` rule
should surface ``TargetFilename``; a ``network_connection`` rule
should surface ``DestinationIp`` / ``DestinationPort``; a
``dns_query`` rule should surface ``QueryName`` — emitting the
process-event field triple ``CommandLine`` / ``Image`` /
``ParentCommandLine`` for everything (the pre-#145 behaviour) was
shallow and forced reviewers to ignore the block on every non-process
rule. :data:`_LOGSOURCE_CATEGORY_TO_FIELDS` drives the category-aware
default so the emitted fields match the events the rule actually
fires against.
"""

from __future__ import annotations

from typing import Any, Dict, List


def _safe(value: str) -> str:
    return (
        value.lower()
        .replace(" ", "-")
        .replace("/", "-")
        .replace(":", "-")
        .replace("_", "-")
    )


# Sigma logsource ``category`` -> recommended ``fields:`` block.
# Field names follow the Sysmon / WindowsEvent / standard Sigma
# vocabulary so the emitted block matches what mainstream Sigma
# rule conversions look for. ``__default__`` keeps the legacy
# process-event triple as the fallback when the category isn't in
# the map (e.g. legacy adapters with bespoke logsource categories).
_LOGSOURCE_CATEGORY_TO_FIELDS: Dict[str, List[str]] = {
    # ---- Endpoint / process family ----
    "process_creation": [
        "CommandLine",
        "ParentCommandLine",
        "Image",
        "ParentImage",
        "User",
    ],
    "process_access": [
        "CallTrace",
        "GrantedAccess",
        "Image",
        "TargetImage",
        "User",
    ],
    "image_load": [
        "Image",
        "ImageLoaded",
        "Signed",
        "Signature",
        "User",
    ],
    # ---- Filesystem family ----
    "file_event": [
        "TargetFilename",
        "Image",
        "ParentImage",
        "User",
    ],
    # ---- Registry family ----
    "registry_event": [
        "TargetObject",
        "Details",
        "Image",
        "User",
    ],
    # ---- Service family ----
    "service_creation": [
        "ServiceName",
        "ServiceFileName",
        "ImagePath",
        "StartType",
    ],
    "service_modification": [
        "ServiceName",
        "ServiceFileName",
        "ImagePath",
        "StartType",
    ],
    # ---- Network / DNS family ----
    "network_connection": [
        "Image",
        "Initiated",
        "DestinationIp",
        "DestinationPort",
        "DestinationHostname",
        "Protocol",
        "User",
    ],
    "dns_query": [
        "QueryName",
        "QueryStatus",
        "QueryResults",
        "Image",
        "User",
    ],
    "dns": [
        "QueryName",
        "QueryStatus",
        "QueryResults",
        "Image",
    ],
    # ---- Auth family ----
    "authentication": [
        "TargetUserName",
        "IpAddress",
        "LogonType",
        "AuthenticationPackageName",
        "WorkstationName",
    ],
    # ---- Cloud / web / proxy family ----
    "cloud_audit": [
        "eventName",
        "userIdentity.userName",
        "sourceIPAddress",
        "userAgent",
        "eventSource",
    ],
    "webserver": [
        "cs-uri-stem",
        "cs-method",
        "cs-User-Agent",
        "c-ip",
        "sc-status",
    ],
    "proxy": [
        "cs-uri-stem",
        "cs-method",
        "cs-User-Agent",
        "c-ip",
        "cs-host",
    ],
    # ---- Email family ----
    "email": [
        "recipient",
        "sender",
        "subject",
        "attachment_name",
        "url",
    ],
    # ---- Hardware / device family ----
    "device_event": [
        "DeviceName",
        "DeviceClassGuid",
        "DeviceInstanceID",
        "EventID",
    ],
    # ---- Threat-intel family. ----
    "threat_intelligence": [
        "ioc_type",
        "ioc_value",
        "threat_actor",
    ],
    # ---- Resource-development / pre-foothold families. ----
    "infrastructure_provisioning": [
        "resource_type",
        "registrar",
        "domain",
    ],
    "account_provisioning": [
        "account_type",
        "provider",
        "username",
    ],
    "certificate_acquisition": [
        "ca",
        "subject_cn",
        "issuer_cn",
    ],
    "tooling_acquisition": [
        "tool_name",
        "marketplace",
        "category",
    ],
    # ---- Legacy-wrapped (no real Splunk / Sigma sourcetype). ----
    "legacy_wrapped": [
        "legacy_subtype",
        "legacy_pack",
        "legacy_capability",
    ],
    "__default__": ["CommandLine", "ParentCommandLine", "Image"],
}


def _fields_for_category(category: str) -> List[str]:
    """Return a fresh copy of the recommended ``fields:`` for ``category``.

    Falls back to the process-event triple when the category isn't in
    the map so legacy adapters with bespoke logsource categories keep
    working. Returns a copy so callers can mutate / extend the list
    without affecting the static mapping.
    """
    return list(
        _LOGSOURCE_CATEGORY_TO_FIELDS.get(
            category, _LOGSOURCE_CATEGORY_TO_FIELDS["__default__"]
        )
    )


def generate_sigma_rule(hint: Dict[str, Any]) -> str:
    """Render a Sigma rule document as YAML text."""
    title = str(hint.get("title", "BlueFire Detection"))
    technique = str(hint.get("mitre_technique", hint.get("mitre_technique_id", "T0000")))
    logsource = hint.get("logsource", {"category": "process_creation", "product": "windows"})
    detection = hint.get(
        "detection",
        {"selection": {"event.provider": "bluefire"}, "condition": "selection"},
    )
    rule_id = _safe(f"bluefire-{title}-{technique}")[:64]
    return "\n".join(
        [
            f"title: {title}",
            f"id: {rule_id}",
            "status: experimental",
            "description: Auto-generated by BlueFire-Nexus detection engine",
            "logsource:",
            f"  category: {logsource.get('category', 'process_creation')}",
            f"  product: {logsource.get('product', 'windows')}",
            "detection:",
            "  selection:",
            *[
                f"    {key}: {value}"
                for key, value in (detection.get("selection") or {}).items()
            ],
            f"  condition: {detection.get('condition', 'selection')}",
            "tags:",
            f"  - attack.{technique.lower()}",
            "level: medium",
            "",
        ]
    )


def build_sigma_rule(run_id: str, module: str, hint: Dict[str, Any]) -> Dict[str, Any]:
    """Compatibility helper used by detection engine."""
    title = str(hint.get("title", f"BlueFire {module} activity ({run_id})"))
    technique = str(hint.get("mitre_technique", hint.get("mitre_technique_id", "T0000")))
    detection = hint.get(
        "detection",
        {"selection": {"module": module, "run_id": run_id}, "condition": "selection"},
    )
    risk_severity = str(hint.get("risk_severity", "medium")).lower()
    if risk_severity not in {"low", "medium", "high", "critical"}:
        risk_severity = "medium"
    risk_score = int(hint.get("risk_score", 50))
    risk_score = max(0, min(100, risk_score))
    detection_doc = str(detection)
    # Pick the recommended ``fields:`` block from the rule's logsource
    # category so an alert reviewer sees columns relevant to the event
    # type (e.g. ``TargetFilename`` for ``file_event``,
    # ``DestinationIp`` for ``network_connection``, ``QueryName`` for
    # ``dns_query``) instead of the legacy process-event triple. Legacy
    # / bespoke logsource categories fall through to the
    # process-event default.
    logsource = hint.get("logsource") or {"category": "process_creation", "product": "windows"}
    if isinstance(logsource, dict):
        category = str(logsource.get("category") or "").strip().lower()
    else:
        category = ""
    fields = _fields_for_category(category)
    # Preserve richer legacy metadata as Sigma fields when the
    # detection block actually carries them — appended to the
    # category-aware base list so a defender still sees the legacy
    # discriminators when they exist.
    for optional_field in (
        "network.transport",
        "network.endpoint",
        "dns.question.name",
        "dns.record_type",
        "legacy.actor",
        "legacy.capability",
        "legacy.mode",
        "legacy.subtype",
        "process.command_line",
        "legacy.risk_severity",
        "legacy.risk_score",
    ):
        if optional_field in detection_doc:
            fields.append(optional_field)
    return {
        "title": title,
        "id": _safe(f"{module}-{run_id}-{technique}")[:64],
        "status": "experimental",
        "description": "Auto-generated by BlueFire-Nexus detection engine",
        "logsource": logsource,
        "detection": detection,
        "fields": sorted(set(fields)),
        "tags": [
            f"attack.{technique.lower()}",
            f"bluefire.risk.{risk_severity}",
        ],
        "level": risk_severity,
        "x_bluefire_risk": {"score": risk_score, "severity": risk_severity},
    }
