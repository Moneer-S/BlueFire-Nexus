"""Local-only operator console.

Static HTML page that lets the operator browse the registered modules,
their capability IO contracts, and the chain pairings the runtime knows
about. Built with the same constraints as the existing run viewer:

- no network calls, no external assets, no ``<script>`` blocks, no
  ``<link>`` to remote stylesheets, no auto-browser-open;
- pure-Python render from the live runtime registry;
- deterministic output (same registry → same HTML, byte for byte);
- HTML escaping on every interpolated value.

The console is a planning aid, not a runner — it does not execute
modules, it does not write scenario YAML, it does not enable any
remote integration. The operator's existing ``run-scenario`` /
``run-operation`` CLI flow is the runner; this page surfaces what
the registry advertises so the operator can decide what to chain
before invoking those commands.
"""

from __future__ import annotations

import html
import textwrap
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .modules import build_runtime_modules
from .modules.contracts import (
    ARTIFACT_TYPES,
    CapabilityIOContract,
    is_meaningful_contract,
)
from .mutations import MUTATION_CATALOG, TARGET_OS_VALUES


_CONSOLE_CSS = """
:root {
  color-scheme: light dark;
  --bg: #0e141b;
  --bg-card: #161e29;
  --bg-code: #0a0f15;
  --border: #233140;
  --fg: #d6e0ec;
  --fg-muted: #8aa1bb;
  --accent: #4f8df7;
  --accent-soft: #1f3e6e;
  --warn: #e6a23c;
  --produce: #2da06d;
  --consume: #c062c0;
}
* { box-sizing: border-box; }
body {
  background: var(--bg);
  color: var(--fg);
  font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
  margin: 0;
  padding: 24px;
}
h1 { font-size: 24px; margin: 0 0 12px; }
h2 { font-size: 18px; margin: 32px 0 12px; padding-bottom: 6px; border-bottom: 1px solid var(--border); }
h3 { font-size: 15px; margin: 20px 0 8px; color: var(--fg-muted); }
.muted { color: var(--fg-muted); }
.warn { color: var(--warn); }
.code { font-family: "SF Mono", Menlo, Consolas, monospace; font-size: 12px; }
.card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 14px 16px;
  margin: 12px 0;
}
.card h3 { margin-top: 0; color: var(--fg); }
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(360px, 1fr));
  gap: 14px;
  margin: 14px 0;
}
.kpis {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
  gap: 10px;
  margin: 14px 0 8px;
}
.kpi { background: var(--bg-card); border: 1px solid var(--border); border-radius: 6px; padding: 10px 14px; }
.kpi b { font-size: 18px; display: block; }
.kpi span { color: var(--fg-muted); font-size: 12px; }
.tag {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 10px;
  background: var(--accent-soft);
  color: var(--fg);
  font-size: 11px;
  margin: 2px 4px 2px 0;
}
.tag.produce { background: rgba(45,160,109,0.18); color: var(--produce); }
.tag.consume { background: rgba(192,98,192,0.18); color: var(--consume); }
.tag.warn { background: rgba(230,162,60,0.16); color: var(--warn); }
.tag.legacy { background: rgba(140,150,170,0.14); color: var(--fg-muted); }
.tag.required { font-weight: 600; }
table { width: 100%; border-collapse: collapse; margin: 8px 0; }
th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--border); vertical-align: top; }
th { color: var(--fg-muted); font-weight: 500; font-size: 12px; }
.section-note { color: var(--fg-muted); font-size: 13px; margin: 0 0 10px; }
.module-name { font-weight: 600; }
.module-techniques { color: var(--fg-muted); font-size: 12px; }
.spec-row { font-size: 12px; padding: 2px 0; }
.spec-row b { font-family: "SF Mono", Menlo, Consolas, monospace; font-weight: 500; color: var(--accent); }
.chain-row { font-size: 12px; padding: 4px 0; border-bottom: 1px dashed var(--border); }
.chain-row:last-child { border-bottom: none; }
.chain-arrow { color: var(--fg-muted); padding: 0 6px; }
.chain-type { color: var(--accent); }
.scenario-row { padding: 6px 0; }
.scenario-name { font-weight: 600; }
.scenario-objective { color: var(--fg-muted); font-size: 12px; }
.footer { color: var(--fg-muted); font-size: 12px; margin-top: 30px; padding-top: 12px; border-top: 1px solid var(--border); }
""".strip()


def build_operator_console(
    output_root: Path,
    *,
    scenarios_dir: Optional[Path] = None,
) -> Path:
    """Build the operator console as ``output_root/operator-console/index.html``.

    Reads the live module registry to render every module's IO
    contract, walks the registry to compute typed chain pairs, and
    surfaces the shipped scenario YAML files (if ``scenarios_dir`` is
    provided or auto-discovered under ``scenarios/``).

    Returns the path to the rendered HTML file. Never starts a server,
    never opens a browser, never writes anywhere outside
    ``output_root/operator-console/``.
    """

    out_dir = (output_root / "operator-console").resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "index.html"

    registry = build_runtime_modules()
    chain_pairs = _compute_chain_pairs(registry)
    scenarios = _list_scenarios(scenarios_dir or _autodiscover_scenarios_dir())

    html_text = _render_console_html(
        registry=registry,
        chain_pairs=chain_pairs,
        scenarios=scenarios,
    )
    out_path.write_text(html_text, encoding="utf-8")
    return out_path


# ---------------------------------------------------------------------------
# Helpers


def _autodiscover_scenarios_dir() -> Optional[Path]:
    """Return the repo's ``scenarios/`` directory, when present.

    Built relative to the package root so a ``pip install -e .`` clone
    finds it; ``None`` when the directory is absent (operators
    installing the package without the repo checkout).
    """

    repo_root = Path(__file__).resolve().parent.parent.parent
    candidate = repo_root / "scenarios"
    if candidate.is_dir():
        return candidate
    return None


def _compute_chain_pairs(
    registry: Mapping[str, Any],
) -> List[Dict[str, Any]]:
    """Compute typed chain edges between producers and consumers.

    Edge: producer P emits artifact type T, consumer C consumes T.
    Edges from a module to itself are skipped. Same producer/type
    pair to multiple consumers becomes multiple edges (one row per
    consumer), so the table reads naturally.

    Sorted by (producer name, artifact type, consumer name) so the
    output is deterministic.
    """

    edges: List[Dict[str, Any]] = []
    for producer_name, producer in sorted(registry.items()):
        contract = getattr(producer, "io_contract", None)
        if not is_meaningful_contract(contract) or not contract.produces:
            continue
        for produced_type in contract.produced_types():
            for consumer_name, consumer in sorted(registry.items()):
                if consumer_name == producer_name:
                    continue
                consumer_contract = getattr(consumer, "io_contract", None)
                if not is_meaningful_contract(consumer_contract) or not consumer_contract.consumes:
                    continue
                if produced_type in consumer_contract.consumed_types():
                    edges.append(
                        {
                            "producer": producer_name,
                            "type": produced_type,
                            "consumer": consumer_name,
                            "consumer_required": produced_type
                            in consumer_contract.required_consumed_types(),
                        }
                    )
    return edges


def _list_scenarios(scenarios_dir: Optional[Path]) -> List[Dict[str, Any]]:
    """Surface every shipped scenario file with its name + objective.

    YAML parsing stays minimal — only the top-level ``name`` /
    ``description`` / ``objective`` keys are read, via a tiny
    line-based parser so we don't pull pyyaml's full dependency
    surface into the operator console module's import path.
    Operators wanting full scenario detail open the YAML directly.
    """

    if scenarios_dir is None or not scenarios_dir.is_dir():
        return []

    rows: List[Dict[str, Any]] = []
    for path in sorted(scenarios_dir.glob("*.yaml")):
        rows.append(_parse_scenario_summary(path))
    return rows


def _parse_scenario_summary(path: Path) -> Dict[str, Any]:
    """Tiny line-based YAML scrape for scenario top-level metadata.

    Reads at most the first 60 lines and looks for ``name:`` /
    ``description:`` / ``objective:`` keys at column 0. Handles two
    real-world value shapes:

    1. **Inline scalar**: ``objective: Text on the same line.`` -
       captured directly with surrounding quotes stripped.
    2. **Literal / folded block scalar**: ``objective: |`` (or
       ``>``) - continuation lines are gathered as long as they are
       more indented than the key, then joined with a single space
       for the preview. Without this branch, shipped scenarios that
       use ``objective: |`` would render with a literal ``|``
       placeholder in the operator console (caught by Codex on PR
       #152: shipped scenarios like ``enterprise_intrusion_chain``
       and ``fin7_initial_access_to_c2`` use the multi-line form).

    Nested structures other than block scalars (e.g. mapping bodies)
    are not parsed; the scrape is intentionally narrow.
    """

    summary: Dict[str, Any] = {
        "filename": path.name,
        "name": "",
        "description": "",
        "objective": "",
    }
    keys = ("name", "description", "objective")
    try:
        with path.open(encoding="utf-8", errors="replace") as fh:
            lines = [raw.rstrip("\n") for raw in fh]
    except OSError:
        return summary

    # Cap how far we scan; top-level metadata always lives near the
    # head of the file, even when block-scalar bodies are multi-line.
    cap = min(len(lines), 60)
    index = 0
    while index < cap:
        line = lines[index]
        if not line or line[0] not in ("n", "d", "o"):
            index += 1
            continue
        next_index = index + 1
        for key in keys:
            prefix = f"{key}:"
            if not line.startswith(prefix) or summary[key]:
                continue
            raw_value = line[len(prefix):].strip()
            # Distinguish between an inline scalar (``key: value``)
            # and a block-scalar header (``key: |``, ``key: >``,
            # plus chomping/indentation suffixes such as ``|-``,
            # ``>+``, ``|2``, ``>+1``, ``|2-`` etc.). YAML's block-
            # scalar grammar is ``|`` / ``>`` + optional chomping
            # (``-`` / ``+``) + optional indentation indicator
            # (``1`` - ``9``) in either order, so any unquoted
            # value starting with ``|`` or ``>`` is a header. An
            # *inline* scalar that legitimately begins with ``|``
            # or ``>`` would be quoted (``"|x"``), and a leading
            # quote falls into the inline branch unchanged.
            looks_like_block = (
                not raw_value or raw_value[0] in ("|", ">")
            )
            if not looks_like_block:
                # Inline scalar form: ``key: value``.
                summary[key] = raw_value.strip('"').strip("'")
                break
            # Block-scalar form. Gather continuation lines that are
            # more indented than the key column (key sits at column
            # 0, so any leading-whitespace line is a continuation;
            # a line that starts at column 0 marks the end of the
            # block). The chomping / indent indicators on the
            # header line are intentionally ignored - the operator
            # console preview joins the body with single spaces,
            # so YAML-spec details about leading-whitespace
            # preservation and trailing-newline handling don't
            # change the rendered preview.
            collected: List[str] = []
            j = index + 1
            while j < len(lines):
                next_line = lines[j]
                if not next_line.strip():
                    j += 1
                    continue
                if next_line[0] not in (" ", "\t"):
                    break
                collected.append(next_line.strip())
                j += 1
            summary[key] = " ".join(part for part in collected if part)
            next_index = j
            break
        index = next_index
    return summary


# ---------------------------------------------------------------------------
# HTML rendering


def _render_console_html(
    *,
    registry: Mapping[str, Any],
    chain_pairs: List[Dict[str, Any]],
    scenarios: List[Dict[str, Any]],
) -> str:
    """Stitch every section together into the single static page."""

    parts: List[str] = []
    parts.append("<!DOCTYPE html>")
    parts.append("<html lang='en'><head>")
    parts.append("<meta charset='utf-8'>")
    parts.append("<meta name='viewport' content='width=device-width, initial-scale=1'>")
    parts.append("<title>BlueFire-Nexus operator console</title>")
    parts.append(f"<style>{_CONSOLE_CSS}</style>")
    parts.append("</head><body>")

    parts.append(_render_header(registry, chain_pairs, scenarios))
    parts.append(_render_kpis(registry, chain_pairs, scenarios))
    parts.append(_render_modules_section(registry))
    parts.append(_render_chain_section(chain_pairs))
    parts.append(_render_mutations_section())
    parts.append(_render_scenarios_section(scenarios))
    parts.append(_render_footer())

    parts.append("</body></html>")
    return "\n".join(parts) + "\n"


def _render_header(
    registry: Mapping[str, Any],
    chain_pairs: List[Dict[str, Any]],
    scenarios: List[Dict[str, Any]],
) -> str:
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return textwrap.dedent(
        f"""
        <h1>BlueFire-Nexus operator console</h1>
        <p class='muted'>Local planning view for the registered module
        catalog and its capability IO contracts. Generated
        <span class='code'>{html.escape(generated_at)}</span>. The
        runtime is unchanged — this page is read-only and never
        starts a server, opens a browser, or makes a network call.</p>
        """
    ).strip()


def _render_kpis(
    registry: Mapping[str, Any],
    chain_pairs: List[Dict[str, Any]],
    scenarios: List[Dict[str, Any]],
) -> str:
    standard_count = sum(1 for name in registry if not name.startswith("legacy_"))
    legacy_count = sum(1 for name in registry if name.startswith("legacy_"))
    artifact_types = sorted(
        {
            spec_type
            for module in registry.values()
            for spec_type in (getattr(module, "io_contract", CapabilityIOContract()).produced_types() or ())
        }
        | {
            spec_type
            for module in registry.values()
            for spec_type in (getattr(module, "io_contract", CapabilityIOContract()).consumed_types() or ())
        }
    )
    # Total catalog candidates across every mutation slot - a single
    # number that quantifies the swap surface available to the
    # mutation engine + scenario planner. Includes the cross-cutting
    # target_os axis.
    mutation_candidate_total = sum(len(v) for v in MUTATION_CATALOG.values()) + len(
        TARGET_OS_VALUES
    )
    return textwrap.dedent(
        f"""
        <div class='kpis'>
          <div class='kpi'><b>{standard_count}</b><span>standard modules</span></div>
          <div class='kpi'><b>{legacy_count}</b><span>legacy adapters</span></div>
          <div class='kpi'><b>{len(chain_pairs)}</b><span>chain pairs</span></div>
          <div class='kpi'><b>{len(scenarios)}</b><span>shipped scenarios</span></div>
          <div class='kpi'><b>{len(artifact_types)} / {len(ARTIFACT_TYPES)}</b><span>artifact types in use</span></div>
          <div class='kpi'><b>{mutation_candidate_total}</b><span>mutation candidates</span></div>
        </div>
        """
    ).strip()


def _render_modules_section(registry: Mapping[str, Any]) -> str:
    parts: List[str] = ["<h2>Modules</h2>"]
    parts.append(
        "<p class='section-note'>Each module declares its capability IO contract "
        "(produces / consumes) plus its declared MITRE ATT&CK technique surface. "
        "Required consumed slots are highlighted; optional slots default to a "
        "documented value when the chain has no upstream emission.</p>"
    )
    parts.append("<div class='grid'>")
    for name in sorted(registry):
        parts.append(_render_module_card(name, registry[name]))
    parts.append("</div>")
    return "\n".join(parts)


def _render_module_card(name: str, module: Any) -> str:
    contract: CapabilityIOContract = getattr(module, "io_contract", CapabilityIOContract())
    techniques = getattr(module, "attack_techniques", ())
    is_legacy = name.startswith("legacy_")

    badges: List[str] = []
    if is_legacy:
        badges.append("<span class='tag legacy'>legacy</span>")
    if contract.not_applicable:
        badges.append("<span class='tag warn'>diagnostic</span>")

    technique_html = ""
    if techniques:
        technique_html = (
            "<div class='module-techniques code'>"
            + html.escape(", ".join(techniques))
            + "</div>"
        )

    if contract.not_applicable:
        body_html = (
            "<p class='muted'>"
            + html.escape(contract.not_applicable_reason)
            + "</p>"
        )
    else:
        body_html = _render_contract_body(contract)

    parts = [
        "<div class='card'>",
        f"<h3 class='module-name'>{html.escape(name)} {' '.join(badges)}</h3>",
        technique_html,
        body_html,
        "</div>",
    ]
    return "\n".join(part for part in parts if part)


def _render_contract_body(contract: CapabilityIOContract) -> str:
    parts: List[str] = []
    if contract.produces:
        parts.append("<h3>Produces</h3>")
        for spec in contract.produces:
            parts.append(_render_spec(spec, kind="produce"))
    if contract.consumes:
        parts.append("<h3>Consumes</h3>")
        for spec in contract.consumes:
            parts.append(_render_spec(spec, kind="consume"))
    if not contract.produces and not contract.consumes:
        parts.append(
            "<p class='muted'>No produces / consumes declared.</p>"
        )
    return "\n".join(parts)


def _render_spec(spec: Any, *, kind: str) -> str:
    type_class = "produce" if kind == "produce" else "consume"
    required = getattr(spec, "required", True)
    required_tag = (
        "<span class='tag required'>required</span>"
        if required and kind == "consume"
        else ""
    )
    key = getattr(spec, "key", "") or ""
    description = getattr(spec, "description", "") or ""
    discriminator = getattr(spec, "produced_if", None)
    discriminator_html = ""
    if discriminator:
        try:
            disc_key, disc_value = discriminator
            if isinstance(disc_value, (tuple, list, set, frozenset)):
                disc_repr = ", ".join(sorted(str(v) for v in disc_value))
            else:
                disc_repr = str(disc_value)
            discriminator_html = (
                f" <span class='tag warn'>when {html.escape(disc_key)}: "
                f"{html.escape(disc_repr)}</span>"
            )
        except (TypeError, ValueError):
            pass
    desc_html = (
        f" — <span class='muted'>{html.escape(description)}</span>"
        if description
        else ""
    )
    key_html = f"<b>{html.escape(key)}</b>" if key else "<b class='muted'>(no key)</b>"
    return (
        f"<div class='spec-row'>"
        f"<span class='tag {type_class}'>{html.escape(spec.type)}</span>"
        f"{key_html}"
        f"{required_tag}"
        f"{discriminator_html}"
        f"{desc_html}"
        f"</div>"
    )


def _render_chain_section(chain_pairs: List[Dict[str, Any]]) -> str:
    parts: List[str] = ["<h2>Chain pairs</h2>"]
    parts.append(
        "<p class='section-note'>Every typed edge between a producing "
        "module and a consuming module the registry knows about. "
        "<b>Required</b> means the consumer's slot is marked required "
        "in its IO contract; optional consumers fall back to a "
        "documented default when the chain has no upstream emission.</p>"
    )
    if not chain_pairs:
        parts.append("<p class='muted'>No chain pairs found.</p>")
        return "\n".join(parts)

    parts.append("<table>")
    parts.append(
        "<thead><tr><th>Producer</th><th>Type</th><th>Consumer</th><th>Required?</th></tr></thead>"
    )
    parts.append("<tbody>")
    for edge in chain_pairs:
        required_label = (
            "<span class='tag required'>required</span>" if edge["consumer_required"] else "optional"
        )
        parts.append(
            "<tr>"
            f"<td class='code'>{html.escape(edge['producer'])}</td>"
            f"<td><span class='tag produce'>{html.escape(edge['type'])}</span></td>"
            f"<td class='code'>{html.escape(edge['consumer'])}</td>"
            f"<td>{required_label}</td>"
            "</tr>"
        )
    parts.append("</tbody></table>")
    return "\n".join(parts)


def _render_mutations_section() -> str:
    """Render the per-module mutation catalog.

    The operator console surfaces every catalog-driven swap the
    capability mutation engine knows about so an operator can
    preview the swap surface before invoking
    ``random_mutation`` / ``suggest_scenario_variants``. The
    rendered shape is a card per module, each card listing the
    field being mutated + every alternative the runtime accepts.

    Reads the live :data:`MUTATION_CATALOG` so a future catalog
    change surfaces here automatically. The cross-cutting
    ``target_os`` axis renders as its own card.
    """

    parts: List[str] = ["<h2>Mutation catalog</h2>"]
    parts.append(
        "<p class='section-note'>Per-module catalog of valid swap "
        "alternatives. <span class='code'>random_mutation</span> "
        "and <span class='code'>suggest_scenario_variants</span> "
        "(in <span class='code'>src.core.mutations</span> + "
        "<span class='code'>src.core.scenario_planner</span>) "
        "draw from this catalog; every value below is one the "
        "runtime module actually accepts.</p>"
    )
    if not MUTATION_CATALOG and not TARGET_OS_VALUES:
        parts.append(
            "<p class='muted'>No mutation slots declared.</p>"
        )
        return "\n".join(parts)

    # Group catalog entries by module so each card lists every
    # mutable field for that module + its alternatives.
    by_module: Dict[str, List[Tuple[str, Tuple[str, ...]]]] = {}
    for (module, key), values in MUTATION_CATALOG.items():
        by_module.setdefault(module, []).append((key, values))
    parts.append("<div class='grid'>")
    for module in sorted(by_module):
        slots = sorted(by_module[module], key=lambda row: row[0])
        body_lines: List[str] = []
        for key, values in slots:
            value_tags = " ".join(
                f"<span class='tag'>{html.escape(v)}</span>"
                for v in sorted(values)
            )
            body_lines.append(
                f"<div class='spec-row'>"
                f"<b>{html.escape(key)}</b> "
                f"<span class='muted'>({len(values)} alternatives)</span>"
                f"<div>{value_tags}</div>"
                f"</div>"
            )
        parts.append(
            "<div class='card'>"
            f"<h3 class='module-name'>{html.escape(module)}</h3>"
            + "".join(body_lines)
            + "</div>"
        )
    # Cross-cutting target_os axis - applies to any step that
    # already declares target_os; render as its own card so the
    # operator sees it isn't tied to a specific module.
    if TARGET_OS_VALUES:
        os_tags = " ".join(
            f"<span class='tag'>{html.escape(v)}</span>"
            for v in sorted(TARGET_OS_VALUES)
        )
        parts.append(
            "<div class='card'>"
            "<h3 class='module-name'>cross-cutting "
            "<span class='tag warn'>any module</span></h3>"
            "<div class='spec-row'>"
            "<b>target_os</b> "
            f"<span class='muted'>({len(TARGET_OS_VALUES)} alternatives;"
            " applies only when the step declares target_os)</span>"
            f"<div>{os_tags}</div>"
            "</div>"
            "</div>"
        )
    parts.append("</div>")
    return "\n".join(parts)


def _render_scenarios_section(scenarios: List[Dict[str, Any]]) -> str:
    parts: List[str] = ["<h2>Shipped scenarios</h2>"]
    if not scenarios:
        parts.append(
            "<p class='muted'>No scenario files found under <span class='code'>scenarios/</span>. "
            "Pass <span class='code'>--scenarios</span> to <span class='code'>operator-console</span> "
            "to point at a different directory.</p>"
        )
        return "\n".join(parts)
    parts.append(
        "<p class='section-note'>Top-level <span class='code'>name</span> / "
        "<span class='code'>description</span> / <span class='code'>objective</span> "
        "from each scenario YAML. Run with "
        "<span class='code'>python -m src.core.cli run-scenario "
        "scenarios/&lt;file&gt;.yaml</span>.</p>"
    )
    parts.append("<div class='grid'>")
    for row in scenarios:
        objective = row.get("objective") or row.get("description") or ""
        parts.append(
            "<div class='card scenario-row'>"
            f"<div class='scenario-name'>{html.escape(row.get('name') or row['filename'])}</div>"
            f"<div class='code muted'>{html.escape(row['filename'])}</div>"
            f"<div class='scenario-objective'>{html.escape(objective)}</div>"
            "</div>"
        )
    parts.append("</div>")
    return "\n".join(parts)


def _render_footer() -> str:
    return textwrap.dedent(
        """
        <div class='footer'>
          <p>This page is generated locally from the live module registry.
          It does not run modules, write scenario YAML, or contact any
          remote service. The operator runs scenarios via
          <span class='code'>python -m src.core.cli run-scenario</span>;
          this console only surfaces what the registry declares so the
          operator can decide what to chain.</p>
        </div>
        """
    ).strip()


__all__ = ["build_operator_console"]
