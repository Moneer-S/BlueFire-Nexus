"""Splunk SPL detection draft generator.

The output is **draft / starter** SPL — emphatically not a
finished detection ready to deploy. Splunk environments differ
enough (index naming, sourcetype routing, field extractions)
that a single generated query cannot be correct everywhere. The
generator instead aims for "useful starter": map the hint's
Sigma logsource onto the most common Splunk sourcetypes for
that telemetry family, surface the selection clause as a
``where`` filter when extractable, and emit run-attribution
``eval`` fields so the search remains traceable to the run that
produced it. A leading comment header makes the draft status
explicit so the operator knows to adjust ``index=`` /
``sourcetype=`` for their environment before deploying.

The earlier generator emitted only ``| makeresults | eval ...``,
which round-tripped the run metadata but never touched any
data source — useful as a self-test, not as a detection. The
``| makeresults`` form is preserved as a fallback when the hint
carries no logsource information (e.g. legacy capability runs
that bypass the Sigma logsource block) so existing tooling that
ingested the metadata-echo shape keeps working.
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
    ("windows", "process_creation"): (
        '(sourcetype="WinEventLog:Security" OR sourcetype="Sysmon" '
        'OR sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational")',
        "(EventCode=4688 OR EventCode=1)",
    ),
    ("linux", "process_creation"): (
        '(sourcetype="linux_audit" OR sourcetype="auditd")',
        "type=EXECVE",
    ),
    ("host", "process_creation"): (
        '(sourcetype="WinEventLog:Security" OR sourcetype="Sysmon" '
        'OR sourcetype="linux_audit")',
        "",
    ),
    ("windows", "network_connection"): (
        '(sourcetype="Sysmon" OR '
        'sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational")',
        "EventCode=3",
    ),
    ("linux", "network_connection"): (
        '(sourcetype="linux_audit" OR sourcetype="auditd")',
        "",
    ),
    ("windows", "dns_query"): (
        '(sourcetype="Sysmon" OR '
        'sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational")',
        "EventCode=22",
    ),
    ("dns", "dns_query"): (
        '(sourcetype="stream:dns" OR sourcetype="dns")',
        "",
    ),
    ("windows", "file_event"): (
        '(sourcetype="Sysmon" OR '
        'sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational")',
        "(EventCode=11 OR EventCode=2)",
    ),
    ("windows", "registry_event"): (
        '(sourcetype="Sysmon" OR '
        'sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational")',
        "(EventCode=12 OR EventCode=13 OR EventCode=14)",
    ),
}


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


def _selection_clauses(detection: Mapping[str, Any] | None) -> List[str]:
    """Render the Sigma ``selection`` block as SPL ``where`` clauses.

    Each Sigma ``field|modifier: value`` becomes a best-effort SPL
    predicate. We support the most common modifiers (``contains`` /
    ``startswith`` / ``endswith``); unknown modifiers fall back to
    plain equality. Lists become ``IN (...)`` clauses. Returns
    a list of ``where``-style strings the caller can join.
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
            field, modifier = key.split("|", 1)
            field = field.strip()
            modifier = modifier.strip().lower()
        else:
            field = key.strip()
        if not field:
            continue
        # Lists become IN (...) clauses — Splunk-friendly form.
        if isinstance(raw_value, (list, tuple)):
            quoted = ", ".join(f'"{_quote(str(v))}"' for v in raw_value)
            clauses.append(f"{field} IN ({quoted})")
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
) -> str:
    """Multi-line backtick comment block flagging this as a draft."""
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
            "` -- Selection (adjust field names to your environment): -- `"
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
