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

from .chain_graph import ChainGraph, build_scenario_graph
from .modes import MODE_METADATA, MODE_NAMES
from .modules import build_runtime_modules
from .modules.contracts import (
    ARTIFACT_TYPES,
    CapabilityIOContract,
    is_meaningful_contract,
)
from .mutations import MUTATION_CATALOG, TARGET_OS_VALUES
from .scenario import load_scenario
from .scenario_planner import ChainState, NextStepSuggestion, offer_next_steps


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
/* Module-category badges. ``standard`` modules get the accent colour;
   each legacy pack gets its own colour so an operator scanning the
   catalog can tell at a glance whether a card is the standard
   surface, an actor research adapter, a c2-protocol research adapter,
   a stealth research adapter, or a tactic-pack legacy class. */
.tag.cat-standard { background: rgba(79,141,247,0.18); color: var(--accent); }
.tag.cat-actor    { background: rgba(192,98,192,0.18); color: var(--consume); }
.tag.cat-c2       { background: rgba(230,162,60,0.18); color: var(--warn); }
.tag.cat-stealth  { background: rgba(140,150,170,0.20); color: var(--fg); }
.tag.cat-tactic   { background: rgba(45,160,109,0.18); color: var(--produce); }
.tag.cat-meta     { background: rgba(140,150,170,0.10); color: var(--fg-muted); }
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
.scenario-graph { margin: 14px 0 6px; }
.scenario-graph-svg { width: 100%; max-width: 100%; height: auto; display: block; background: var(--bg-code); border: 1px solid var(--border); border-radius: 4px; padding: 6px; }
.scenario-graph-legend { font-size: 11px; color: var(--fg-muted); margin: 6px 0 0; }
.scenario-graph-legend .swatch { display: inline-block; width: 18px; height: 2px; vertical-align: middle; margin: 0 4px 2px 0; }
.scenario-graph-warning { font-size: 12px; padding: 4px 0; }
.scenario-graph-warning .severity { font-family: "SF Mono", Menlo, Consolas, monospace; padding: 1px 6px; border-radius: 4px; font-size: 10px; margin-right: 6px; }
.severity-missing_required { background: rgba(192,72,72,0.18); color: #e07c7c; }
.severity-high_value_unused { background: rgba(230,162,60,0.18); color: var(--warn); }
.severity-unused_emission { background: rgba(140,150,170,0.14); color: var(--fg-muted); }
.scenario-graph-empty { color: var(--fg-muted); font-size: 12px; font-style: italic; }
.scenario-graph-attack { font-size: 11px; padding: 6px 0 4px; }
.scenario-suggestions { margin: 10px 0 0; }
.scenario-suggestions h4 { font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; color: var(--fg-muted); margin: 8px 0 4px; }
.scenario-suggestion { font-size: 12px; padding: 4px 0; border-bottom: 1px dashed var(--border); }
.scenario-suggestion:last-child { border-bottom: none; }
.scenario-suggestion .rank-tier { font-family: "SF Mono", Menlo, Consolas, monospace; padding: 1px 6px; border-radius: 4px; font-size: 10px; margin-right: 6px; }
.rank-perfect_fit { background: rgba(45,160,109,0.18); color: var(--produce); }
.rank-good_fit    { background: rgba(79,141,247,0.18); color: var(--accent); }
.rank-partial_fit { background: rgba(230,162,60,0.18); color: var(--warn); }
.rank-chain_entry { background: rgba(140,150,170,0.16); color: var(--fg-muted); }
.scenario-suggestion-rationale { color: var(--fg-muted); font-size: 11px; margin-left: 0; padding-left: 0; }
.scenario-suggestions-empty { color: var(--fg-muted); font-style: italic; font-size: 12px; }
.mode-card { border-left: 4px solid var(--accent); }
.mode-card.mode-simulate { border-left-color: var(--produce); }
.mode-card.mode-emulate { border-left-color: var(--warn); }
.mode-card.mode-live-lab { border-left-color: #c04848; }
.mode-title { display: flex; align-items: center; gap: 10px; margin: 0 0 6px; font-size: 16px; }
.mode-name { font-weight: 600; font-family: "SF Mono", Menlo, Consolas, monospace; }
.mode-badge { font-size: 10px; padding: 2px 6px; border-radius: 4px; }
.mode-badge.unattended { background: rgba(45,160,109,0.18); color: var(--produce); }
.mode-badge.confirm { background: rgba(192,72,72,0.18); color: #e07c7c; }
.mode-section { font-size: 12px; margin: 8px 0 0; }
.mode-section h4 { font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; color: var(--fg-muted); margin: 8px 0 4px; }
.mode-section ul { margin: 0; padding-left: 18px; }
.mode-section li { padding: 1px 0; }
.mode-config-key { font-family: "SF Mono", Menlo, Consolas, monospace; color: var(--accent); }
.mode-config-value { font-family: "SF Mono", Menlo, Consolas, monospace; color: var(--fg); }
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
    resolved_scenarios_dir = scenarios_dir or _autodiscover_scenarios_dir()
    scenarios = _list_scenarios(resolved_scenarios_dir)
    scenario_graphs = _build_scenario_graphs(resolved_scenarios_dir, registry)

    html_text = _render_console_html(
        registry=registry,
        chain_pairs=chain_pairs,
        scenarios=scenarios,
        scenario_graphs=scenario_graphs,
    )
    out_path.write_text(html_text, encoding="utf-8")
    return out_path


# ---------------------------------------------------------------------------
# Helpers


# Module category vocabulary. A registered module belongs to exactly
# one of these. ``standard`` covers every module that isn't part of the
# legacy capability surface; the other categories map to the legacy
# pack vocabulary in :mod:`src.core.legacy_controls`.
MODULE_CATEGORIES: Tuple[str, ...] = (
    "standard",
    "actor",
    "c2",
    "stealth",
    "tactic",
    "meta",
)

# Legacy module-name → category mapping. Hard-coded against the
# current registered set so the operator console stays decoupled from
# legacy_controls' pack/capability machinery (which is keyed on
# capability names, not module names). Keeping the mapping here also
# means a renamed legacy module surfaces a "legacy" category fallback
# instead of silently mis-categorising.
_LEGACY_MODULE_CATEGORY: Dict[str, str] = {
    "legacy_actor_profile": "actor",
    "legacy_apt28_research": "actor",
    "legacy_apt29_research": "actor",
    "legacy_apt32_research": "actor",
    "legacy_apt38_research": "actor",
    "legacy_apt41_research": "actor",
    "legacy_protocol_research": "c2",
    "legacy_stealth_research": "stealth",
    "legacy_collection": "tactic",
    "legacy_credential_access": "tactic",
    "legacy_impact": "tactic",
    "legacy_lateral_movement": "tactic",
    "legacy_privilege_escalation": "tactic",
    "legacy_capability_summary": "meta",
}


def _categorize_module(name: str) -> str:
    """Return the category bucket for a registered module name.

    Categories: ``standard`` (the canonical capability surface) /
    ``actor`` / ``c2`` / ``stealth`` / ``tactic`` / ``meta`` (legacy
    pack groupings). Unknown ``legacy_*`` modules fall back to
    ``meta`` so the badge still renders rather than going silently
    uncategorised.
    """

    if not name.startswith("legacy_"):
        return "standard"
    return _LEGACY_MODULE_CATEGORY.get(name, "meta")


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


def _build_scenario_graphs(
    scenarios_dir: Optional[Path],
    registry: Mapping[str, Any],
) -> List[Dict[str, Any]]:
    """Load every shipped scenario and compute its static chain graph.

    Each entry carries the scenario's filename, its parsed name and
    objective, and either a :class:`ChainGraph` (when the YAML loads
    cleanly) or an error string (when ``load_scenario`` raises). The
    operator console renders graphs inline next to the modules /
    chain-pairs sections; callers that just want the metadata should
    keep using :func:`_list_scenarios` to avoid the full YAML parse.

    Returns an empty list when ``scenarios_dir`` is missing or empty.
    """

    if scenarios_dir is None or not scenarios_dir.is_dir():
        return []

    rows: List[Dict[str, Any]] = []
    for path in sorted(scenarios_dir.glob("*.yaml")):
        entry: Dict[str, Any] = {
            "filename": path.name,
            "name": "",
            "objective": "",
            "graph": None,
            "error": None,
        }
        try:
            scenario = load_scenario(path)
        except Exception as exc:
            # ``load_scenario`` raises on malformed YAML; treat the
            # malformed scenario as a partial entry so the rest of the
            # scenarios still render. The console surfaces the error
            # text inline so the operator sees what failed.
            entry["error"] = f"failed to load: {exc.__class__.__name__}"
            rows.append(entry)
            continue
        entry["name"] = scenario.name or scenario.id or path.stem
        entry["objective"] = (scenario.objective or "").strip()
        # Surface the scenario's declared ATT&CK technique surface so
        # the per-card KPI strip can render the count without re-
        # parsing YAML. Cleans empty entries the loader may have
        # passed through verbatim.
        entry["attack_techniques"] = tuple(
            str(t).strip() for t in (scenario.attack_techniques or ()) if str(t).strip()
        )
        try:
            entry["graph"] = build_scenario_graph(
                scenario.steps, registry=registry
            )
        except Exception as exc:  # pragma: no cover - graph builder is robust
            entry["error"] = f"graph build failed: {exc.__class__.__name__}"
        # Compute next-step planner suggestions from the scenario's
        # produced types. This mirrors what the planner-suggest CLI
        # does (``_chain_state_from_scenario`` in :mod:`src.core.cli`)
        # so the inline panel and the CLI agree on the ranking. Skips
        # silently when graph construction failed -- the suggestions
        # block then renders the empty-state copy.
        entry["planner_suggestions"] = _planner_suggestions_for(
            entry.get("graph"), registry
        )
        rows.append(entry)
    return rows


def _planner_suggestions_for(
    graph: Optional[ChainGraph],
    registry: Mapping[str, Any],
) -> Tuple[NextStepSuggestion, ...]:
    """Return up to 5 ranked next-step suggestions for ``graph``.

    Mirrors :func:`src.core.cli._chain_state_from_scenario`'s state-
    building rule so the inline panel and the planner-suggest CLI
    agree on the ranking. Walks the graph nodes' ``produces`` to
    compose the produced-types frozenset; the planner does the
    actual ranking via :func:`src.core.scenario_planner.offer_next_steps`.

    Returns an empty tuple when ``graph`` is ``None`` (graph build
    failed) so the caller renders the empty-state copy without
    raising.
    """

    if graph is None:
        return ()
    produced_types: set[str] = set()
    for node in graph.nodes:
        for produced_type in node.produces:
            produced_types.add(produced_type)
    state = ChainState(produced_types=frozenset(produced_types))
    return tuple(offer_next_steps(state, registry=registry, limit=5))


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
    scenario_graphs: Optional[List[Dict[str, Any]]] = None,
) -> str:
    """Stitch every section together into the single static page."""

    scenario_graphs = scenario_graphs or []
    parts: List[str] = []
    parts.append("<!DOCTYPE html>")
    parts.append("<html lang='en'><head>")
    parts.append("<meta charset='utf-8'>")
    parts.append("<meta name='viewport' content='width=device-width, initial-scale=1'>")
    parts.append("<title>BlueFire-Nexus operator console</title>")
    parts.append(f"<style>{_CONSOLE_CSS}</style>")
    parts.append("</head><body>")

    parts.append(_render_header(registry, chain_pairs, scenarios))
    parts.append(_render_kpis(registry, chain_pairs, scenarios, scenario_graphs))
    parts.append(_render_modules_section(registry))
    parts.append(_render_chain_section(chain_pairs))
    parts.append(_render_mutations_section())
    parts.append(_render_scenarios_section(scenarios))
    parts.append(_render_scenario_graphs_section(scenario_graphs))
    parts.append(_render_modes_section())
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
    scenario_graphs: Optional[List[Dict[str, Any]]] = None,
) -> str:
    scenario_graphs = scenario_graphs or []
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
    # Scenario-graph KPIs: explicit-edge count + warning count summed
    # across every shipped scenario. Lets the operator see at a glance
    # how much typed propagation the catalog of scenarios actually
    # demonstrates AND how many coverage gaps the static analyser
    # surfaced. Ignores rows where the graph build failed (entry has
    # ``error`` set instead of a ``ChainGraph``).
    explicit_edges_total = 0
    warnings_total = 0
    for entry in scenario_graphs:
        graph = entry.get("graph")
        if graph is None:
            continue
        explicit_edges_total += sum(1 for edge in graph.edges if edge.explicit)
        warnings_total += len(graph.warnings)
    # ATT&CK technique surface: dedup across every module's declared
    # ``attack_techniques`` tuple (covers both standard and legacy
    # adapters) so the operator sees how broad the catalog's defender-
    # facing surface is in one glance. Empty / missing tuples are
    # silently skipped.
    attack_technique_set: set[str] = set()
    for module in registry.values():
        for technique in getattr(module, "attack_techniques", ()) or ():
            cleaned = str(technique).strip()
            if cleaned:
                attack_technique_set.add(cleaned)
    # Per-scenario: count scenarios that declare ANY ``attack_coverage``.
    # Defender value: high-coverage scenarios shape detection content
    # in a way single-technique scenarios can't.
    scenarios_with_attack = sum(
        1 for entry in scenario_graphs if entry.get("attack_techniques")
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
          <div class='kpi'><b>{explicit_edges_total}</b><span>scenario explicit edges</span></div>
          <div class='kpi'><b>{warnings_total}</b><span>scenario chain warnings</span></div>
          <div class='kpi'><b>{len(attack_technique_set)}</b><span>ATT&amp;CK techniques in catalog</span></div>
          <div class='kpi'><b>{scenarios_with_attack}</b><span>scenarios with ATT&amp;CK coverage</span></div>
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
    category = _categorize_module(name)

    badges: List[str] = []
    # Category badge always renders so an operator scanning the
    # catalog sees standard / actor / c2 / stealth / tactic / meta at
    # a glance — beyond just the legacy/standard binary.
    badges.append(
        f"<span class='tag cat-{html.escape(category)}'>{html.escape(category)}</span>"
    )
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


def _render_scenario_graphs_section(
    scenario_graphs: List[Dict[str, Any]],
) -> str:
    """Render one chain-graph card per shipped scenario.

    Each card shows:

    - the scenario name + objective preview;
    - a per-scenario KPI strip (steps / explicit edges / implicit
      edges / warnings);
    - an inline SVG flowchart with one box per step plus typed arcs
      for every chain edge (explicit edges in accent colour, implicit
      edges in the muted colour);
    - an edge table that surfaces every (source, type, target) row
      so an operator can correlate the SVG against the YAML;
    - the warnings list (``missing_required`` / ``high_value_unused``
      / ``unused_emission``) when any are present.

    The SVG is fully inline (``<svg>`` element with no external
    references), uses inline ``fill`` / ``stroke`` attributes (not
    external CSS classes), and never includes ``<script>`` or
    ``<foreignObject>``. Safe for a fully-offline static page.
    """

    parts: List[str] = ["<h2>Scenario chain graphs</h2>"]
    parts.append(
        "<p class='section-note'>Static chain graph for each shipped "
        "scenario, computed from the YAML alone (no execution). Nodes "
        "are scenario steps; edges are typed propagation between a "
        "producing step and a consuming step. <b>Explicit</b> edges "
        "come from <span class='code'>*_from_step</span> references "
        "in the scenario; <b>implicit</b> edges are inferred from the "
        "consumer's IO contract when an earlier producer matches the "
        "consumed type. Coverage gaps surface as warnings under each "
        "graph.</p>"
    )
    if not scenario_graphs:
        parts.append(
            "<p class='muted'>No scenario graphs available — pass "
            "<span class='code'>--scenarios</span> to "
            "<span class='code'>operator-console</span> to point at a "
            "scenarios directory.</p>"
        )
        return "\n".join(parts)

    parts.append("<div class='grid'>")
    for entry in scenario_graphs:
        parts.append(_render_scenario_graph_card(entry))
    parts.append("</div>")
    return "\n".join(parts)


def _render_scenario_graph_card(entry: Mapping[str, Any]) -> str:
    """Render a single per-scenario chain-graph card."""

    filename = str(entry.get("filename") or "")
    name = str(entry.get("name") or filename)
    objective = str(entry.get("objective") or "")
    error = entry.get("error")
    graph: Optional[ChainGraph] = entry.get("graph")

    pieces: List[str] = []
    pieces.append("<div class='card scenario-graph'>")
    pieces.append(
        f"<div class='scenario-name'>{html.escape(name)}</div>"
        f"<div class='code muted'>{html.escape(filename)}</div>"
    )
    if objective:
        # Trim long objectives for the card preview but keep enough
        # context to identify the scenario at a glance.
        preview = objective if len(objective) <= 320 else objective[:317] + "..."
        pieces.append(
            f"<div class='scenario-objective'>{html.escape(preview)}</div>"
        )

    if error or graph is None:
        pieces.append(
            "<p class='scenario-graph-empty'>Chain graph unavailable: "
            f"{html.escape(str(error or 'load_scenario returned no steps'))}</p>"
        )
        pieces.append("</div>")
        return "\n".join(pieces)

    explicit_count = sum(1 for edge in graph.edges if edge.explicit)
    implicit_count = sum(1 for edge in graph.edges if not edge.explicit)
    attack_techniques = tuple(entry.get("attack_techniques") or ())
    pieces.append(
        "<div class='kpis'>"
        f"<div class='kpi'><b>{len(graph.nodes)}</b><span>steps</span></div>"
        f"<div class='kpi'><b>{explicit_count}</b><span>explicit edges</span></div>"
        f"<div class='kpi'><b>{implicit_count}</b><span>implicit edges</span></div>"
        f"<div class='kpi'><b>{len(graph.warnings)}</b><span>warnings</span></div>"
        f"<div class='kpi'><b>{len(attack_techniques)}</b>"
        f"<span>ATT&amp;CK techniques</span></div>"
        "</div>"
    )
    # ATT&CK technique chips: render every declared technique as a
    # tag below the KPI strip so a defender sees the coverage surface
    # at a glance. Skipped silently when the scenario doesn't declare
    # any ``attack_coverage:``.
    if attack_techniques:
        chips = " ".join(
            f"<span class='tag'>{html.escape(t)}</span>"
            for t in attack_techniques
        )
        pieces.append(
            "<div class='scenario-graph-attack code'>"
            f"<span class='muted'>declared ATT&amp;CK:</span> {chips}"
            "</div>"
        )
    pieces.append(_render_scenario_graph_svg(graph))
    pieces.append(
        "<p class='scenario-graph-legend'>"
        "<span class='swatch' style='background:#4f8df7'></span>explicit "
        "(<span class='code'>*_from_step</span>) "
        "&nbsp;&nbsp;"
        "<span class='swatch' style='background:#8aa1bb'></span>implicit "
        "(contract-derived)"
        "</p>"
    )
    pieces.append(_render_scenario_graph_edges_table(graph))
    if graph.warnings:
        pieces.append(_render_scenario_graph_warnings(graph))
    pieces.append(
        _render_scenario_planner_suggestions(
            tuple(entry.get("planner_suggestions") or ())
        )
    )
    pieces.append("</div>")
    return "\n".join(pieces)


def _render_scenario_planner_suggestions(
    suggestions: Tuple[NextStepSuggestion, ...],
) -> str:
    """Render the per-scenario planner-suggestions panel.

    Mirrors the ``planner-suggest`` CLI output: the same ranked list,
    same rank tiers, same rationale lines. The console adds inline
    rank-tier badges so an operator scanning the card sees
    ``perfect_fit`` / ``good_fit`` / ``partial_fit`` / ``chain_entry``
    at a glance.

    Empty ``suggestions`` (e.g. graph build failed, registry rejected
    every module) renders an italic empty-state line so the panel
    structure stays visible without showing fake content.
    """

    parts: List[str] = ["<div class='scenario-suggestions'>"]
    parts.append("<h4>Suggested next steps</h4>")
    if not suggestions:
        parts.append(
            "<p class='scenario-suggestions-empty'>No next-step "
            "suggestions: scenario emits no chain-relevant artifacts "
            "or every registered module rejected the chain state.</p>"
        )
        parts.append("</div>")
        return "\n".join(parts)
    for suggestion in suggestions:
        parts.append("<div class='scenario-suggestion'>")
        parts.append(
            "<span class='rank-tier rank-{rank}'>{rank}</span>"
            "<span class='code'>{module}</span> "
            "<span class='muted'>(score {score})</span>".format(
                rank=html.escape(suggestion.rank),
                module=html.escape(suggestion.module),
                score=html.escape(f"{suggestion.score:.2f}"),
            )
        )
        parts.append(
            "<div class='scenario-suggestion-rationale'>"
            f"{html.escape(suggestion.rationale)}"
            "</div>"
        )
        parts.append("</div>")
    parts.append("</div>")
    return "\n".join(parts)


# Layout constants for the scenario graph SVG. Picked so a 12-step
# scenario (the enterprise chain) fits in roughly 1500px wide which
# the surrounding ``.scenario-graph-svg`` rule then scales to the
# card width via ``width: 100%; height: auto`` — the SVG retains its
# aspect ratio whether the card is 360px wide or 800px.
_SVG_NODE_WIDTH = 110
_SVG_NODE_HEIGHT = 50
_SVG_NODE_GAP = 30
_SVG_NODE_TOP = 90  # Y of node-rect top; arcs above span y=10..90.
_SVG_PADDING = 10
_SVG_LABEL_AREA = 70  # Y space below the node row for labels.
_SVG_EXPLICIT_COLOR = "#4f8df7"
_SVG_IMPLICIT_COLOR = "#8aa1bb"
_SVG_NODE_FILL = "#1f3e6e"
_SVG_NODE_STROKE = "#233140"
_SVG_TEXT_COLOR = "#d6e0ec"
_SVG_TEXT_MUTED = "#8aa1bb"


def _render_scenario_graph_svg(graph: ChainGraph) -> str:
    """Render the scenario chain graph as an inline static SVG flowchart.

    Layout: every step is a labelled rectangle in a single horizontal
    row. Every edge is an arc above the row, source-center-top to
    target-center-top, with the artifact-type label centred above the
    arc apex. The arc apex height scales with the source-to-target
    span so adjacent edges have shallow arcs and long-range edges
    bow higher (no overlap when the arc heights differ). Returns
    ``""`` when the graph has no nodes.

    The SVG is self-contained: no external assets, no ``<script>``,
    no CSS class names — every fill / stroke / font-size lives inline
    so the output is portable to any HTML renderer.
    """

    if not graph.nodes:
        return ""
    node_count = len(graph.nodes)
    stride = _SVG_NODE_WIDTH + _SVG_NODE_GAP
    width = _SVG_PADDING * 2 + stride * node_count - _SVG_NODE_GAP
    height = _SVG_NODE_TOP + _SVG_NODE_HEIGHT + _SVG_LABEL_AREA + _SVG_PADDING

    # Layout: x position for each step's bounding box.
    node_x: Dict[str, int] = {}
    for index, node in enumerate(graph.nodes):
        node_x[node.step_id] = _SVG_PADDING + stride * index

    parts: List[str] = []
    parts.append(
        f"<svg class='scenario-graph-svg' role='img' aria-label='scenario chain graph' "
        f"viewBox='0 0 {width} {height}' xmlns='http://www.w3.org/2000/svg'>"
    )
    # <defs> with arrow markers for each edge colour. Defining markers
    # once and referencing them keeps the SVG compact even when the
    # scenario has many edges.
    parts.append(
        "<defs>"
        + _svg_arrow_marker("arrow-explicit", _SVG_EXPLICIT_COLOR)
        + _svg_arrow_marker("arrow-implicit", _SVG_IMPLICIT_COLOR)
        + "</defs>"
    )

    # Draw edges first so node rectangles render on top of arc tails.
    for edge in graph.edges:
        src_x = node_x.get(edge.source_step_id)
        tgt_x = node_x.get(edge.target_step_id)
        if src_x is None or tgt_x is None:
            continue
        parts.append(_svg_edge_arc(edge, src_x, tgt_x))

    # Draw node rectangles + step-id label + module label.
    for node in graph.nodes:
        x = node_x[node.step_id]
        parts.append(_svg_node_rect(node, x))

    parts.append("</svg>")
    return "\n".join(parts)


def _svg_arrow_marker(marker_id: str, colour: str) -> str:
    """Return a tiny ``<marker>`` element for an arrowhead at the line end."""

    return (
        f"<marker id='{marker_id}' viewBox='0 0 8 8' refX='7' refY='4' "
        f"markerWidth='6' markerHeight='6' orient='auto'>"
        f"<path d='M0,0 L8,4 L0,8 z' fill='{colour}'/>"
        f"</marker>"
    )


def _svg_node_rect(node: Any, x: int) -> str:
    """Return SVG for a single step rectangle with step_id + module label."""

    width = _SVG_NODE_WIDTH
    height = _SVG_NODE_HEIGHT
    centre_x = x + width // 2
    text_y_id = _SVG_NODE_TOP + 22
    text_y_module = _SVG_NODE_TOP + 38
    label_y = _SVG_NODE_TOP + height + 18
    return (
        f"<rect x='{x}' y='{_SVG_NODE_TOP}' width='{width}' height='{height}' "
        f"rx='6' ry='6' fill='{_SVG_NODE_FILL}' stroke='{_SVG_NODE_STROKE}'/>"
        f"<text x='{centre_x}' y='{text_y_id}' text-anchor='middle' "
        f"font-size='11' font-family='monospace' fill='{_SVG_TEXT_COLOR}'>"
        f"{html.escape(_clip_label(str(node.step_id), 16))}</text>"
        f"<text x='{centre_x}' y='{text_y_module}' text-anchor='middle' "
        f"font-size='10' fill='{_SVG_TEXT_MUTED}'>"
        f"{html.escape(_clip_label(str(node.module), 16))}</text>"
        f"<text x='{centre_x}' y='{label_y}' text-anchor='middle' "
        f"font-size='9' fill='{_SVG_TEXT_MUTED}'>step {node.step_index + 1}</text>"
    )


def _svg_edge_arc(edge: Any, src_x: int, tgt_x: int) -> str:
    """Return SVG for a single edge arc + label.

    The arc bows upward; its apex height grows with the source-target
    span so long-range edges sit visually above shorter ones and the
    label is reachable for every edge regardless of length.
    """

    src_centre = src_x + _SVG_NODE_WIDTH // 2
    tgt_centre = tgt_x + _SVG_NODE_WIDTH // 2
    # Arc apex y: lower (smaller y) means higher up. Adjacent edges arc
    # at y=60 (just above the node top of 90); a 5-step span arcs at
    # y=15 (near the SVG top edge); clamp to the SVG padding.
    span = abs(tgt_centre - src_centre)
    apex_y = max(_SVG_PADDING + 5, _SVG_NODE_TOP - 25 - span // 12)
    mid_x = (src_centre + tgt_centre) // 2
    colour = _SVG_EXPLICIT_COLOR if edge.explicit else _SVG_IMPLICIT_COLOR
    marker_id = "arrow-explicit" if edge.explicit else "arrow-implicit"
    label = html.escape(str(edge.artifact_type))
    label_y = max(_SVG_PADDING, apex_y - 6)
    return (
        f"<path d='M{src_centre} {_SVG_NODE_TOP} "
        f"Q{mid_x} {apex_y} {tgt_centre} {_SVG_NODE_TOP}' "
        f"stroke='{colour}' stroke-width='1.5' fill='none' "
        f"marker-end='url(#{marker_id})'/>"
        f"<text x='{mid_x}' y='{label_y}' text-anchor='middle' "
        f"font-size='9' fill='{colour}'>{label}</text>"
    )


def _clip_label(text: str, limit: int) -> str:
    """Trim a label to ``limit`` characters with an ellipsis when too long."""

    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)] + "…"


def _render_scenario_graph_edges_table(graph: ChainGraph) -> str:
    """Render the per-scenario edge list as a compact HTML table."""

    if not graph.edges:
        return (
            "<p class='muted scenario-graph-empty'>"
            "No typed propagation between steps in this scenario.</p>"
        )
    rows: List[str] = ["<table>"]
    rows.append(
        "<thead><tr>"
        "<th>Source</th><th>Type</th><th>Target</th><th>Edge</th>"
        "</tr></thead><tbody>"
    )
    for edge in graph.edges:
        edge_label = (
            "<span class='tag'>explicit</span>"
            if edge.explicit
            else "<span class='tag legacy'>implicit</span>"
        )
        rows.append(
            "<tr>"
            f"<td class='code'>{html.escape(edge.source_step_id)}</td>"
            f"<td><span class='tag produce'>{html.escape(edge.artifact_type)}</span></td>"
            f"<td class='code'>{html.escape(edge.target_step_id)}</td>"
            f"<td>{edge_label}</td>"
            "</tr>"
        )
    rows.append("</tbody></table>")
    return "\n".join(rows)


def _render_scenario_graph_warnings(graph: ChainGraph) -> str:
    """Render the per-scenario warnings list."""

    rows: List[str] = ["<h3>Coverage warnings</h3>"]
    for warning in graph.warnings:
        css_class = f"severity-{warning.severity}"
        rows.append(
            "<div class='scenario-graph-warning'>"
            f"<span class='severity {css_class}'>{html.escape(warning.severity)}</span>"
            f"<span class='code'>{html.escape(warning.step_id)}</span> "
            f"<span class='tag warn'>{html.escape(warning.artifact_type)}</span> "
            f"<span class='muted'>{html.escape(warning.message)}</span>"
            "</div>"
        )
    return "\n".join(rows)


def _render_modes_section() -> str:
    """Render the per-mode info card grid.

    Each card mirrors a :class:`src.core.modes.ModeDefinition` from
    :data:`src.core.modes.MODE_METADATA`. The section is purely
    informational - the console never writes a mode override, never
    enables a mode, and never starts execution. Operators apply the
    config patch via the ordinary config-writer path after reviewing
    the description, gates, side effects, and warnings shown here.
    """

    parts: List[str] = ["<h2>Execution modes</h2>"]
    parts.append(
        "<p class='section-note'>The runtime supports three execution "
        "modes. <span class='code'>simulate</span> is the safe-by-default "
        "baseline; <span class='code'>emulate</span> writes deeper "
        "artifacts but stays offline; <span class='code'>live-lab</span> "
        "performs real network/process side effects and requires explicit "
        "confirmation. Mode metadata is read from "
        "<span class='code'>src.core.modes</span> - see "
        "<span class='code'>python -m src.core.cli explain-mode &lt;mode&gt;</span> "
        "for the same data on the terminal.</p>"
    )
    parts.append("<div class='grid'>")
    for mode_name in MODE_NAMES:
        parts.append(_render_mode_card(mode_name))
    parts.append("</div>")
    return "\n".join(parts)


def _render_mode_card(mode_name: str) -> str:
    definition = MODE_METADATA[mode_name]
    css_safe_name = mode_name.replace("_", "-")
    badge_class = "unattended" if definition.safe_for_unattended else "confirm"
    badge_label = (
        "safe for unattended" if definition.safe_for_unattended
        else "requires explicit confirmation"
    )
    pieces: List[str] = [
        f"<div class='card mode-card mode-{html.escape(css_safe_name)}'>"
    ]
    pieces.append(
        "<h3 class='mode-title'>"
        f"<span class='mode-name'>{html.escape(definition.name)}</span>"
        f"<span class='mode-badge {badge_class}'>"
        f"{html.escape(badge_label)}</span>"
        "</h3>"
    )
    pieces.append(
        f"<p class='muted'>{html.escape(definition.description)}</p>"
    )

    pieces.append("<div class='mode-section'>")
    pieces.append("<h4>Config overrides</h4>")
    if definition.config_overrides:
        pieces.append("<ul>")
        for key, value in definition.config_overrides:
            pieces.append(
                "<li>"
                f"<span class='mode-config-key'>{html.escape(key)}</span> "
                "= "
                f"<span class='mode-config-value'>{html.escape(repr(value))}</span>"
                "</li>"
            )
        pieces.append("</ul>")
    else:
        pieces.append("<p class='muted'>(none)</p>")
    pieces.append("</div>")

    pieces.append("<div class='mode-section'>")
    pieces.append("<h4>Required gates</h4>")
    if definition.required_gates:
        pieces.append("<ul>")
        for gate in definition.required_gates:
            pieces.append(f"<li>{html.escape(gate)}</li>")
        pieces.append("</ul>")
    else:
        pieces.append("<p class='muted'>(none)</p>")
    pieces.append("</div>")

    pieces.append("<div class='mode-section'>")
    pieces.append("<h4>Side effects</h4>")
    if definition.side_effects:
        pieces.append("<ul>")
        for effect in definition.side_effects:
            pieces.append(f"<li>{html.escape(effect)}</li>")
        pieces.append("</ul>")
    else:
        pieces.append("<p class='muted'>(none)</p>")
    pieces.append("</div>")

    if definition.warnings:
        pieces.append("<div class='mode-section'>")
        pieces.append("<h4 class='warn'>Warnings</h4>")
        pieces.append("<ul>")
        for warning in definition.warnings:
            pieces.append(f"<li class='warn'>{html.escape(warning)}</li>")
        pieces.append("</ul>")
        pieces.append("</div>")

    pieces.append("</div>")
    return "\n".join(pieces)


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
