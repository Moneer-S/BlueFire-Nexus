# Changelog

All notable changes to BlueFire-Nexus are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The detailed merged-PR history lives in
[`docs/reports/next_roadmap.md`](docs/reports/next_roadmap.md).
This file summarises the deltas at the version-tag granularity.

## [Unreleased]

### Added

- Fifth `previous_step_results` consumer pair plumbed into the
  shipped `enterprise_intrusion_chain` scenario:
  `resource_development → command_control` endpoint axis. The
  `command_control` module gained an optional
  `c2_endpoint_from_step` step param that picks up the upstream
  step's `artifacts.target` (or first entry of `artifacts.targets`)
  and shapes it into a c2_url (`https://<host>/c2` for hostnames;
  upstream values that already include a scheme are used verbatim).
  Explicit `c2_url` always wins. The scenario's `c2-channel` step
  now propagates from `stage-infrastructure` rather than hardcoding
  the C2 URL, modelling how an attacker-owned domain registered in
  resource_development becomes the C2 endpoint a few steps later.
- `ResourceDevelopmentModule.artifacts` now surfaces the registered
  `target` (e.g. the registered domain / vps / cert) so downstream
  propagation consumers can read it. Previously the param value
  was only in step config and not visible in the artifact dict.
- **Loop F — flagship scenario realism + chain narrative
  coherence** (PRs #118-#124). The scenario's `objective:` block
  is now surfaced consistently across every output surface — the
  static dashboard header (paragraph-aware), `report.md`'s new
  `## Scenario objective` section, and the offline copilot's
  `copilot_narrative.md` body and YAML metadata header — so a
  defender opening any one of those gets the same chain story
  rather than just step-status counts.
- Each propagation edge in the manifest now carries
  `from_module` and a defender-facing `narrative` field
  (`credential_access targets the host produced by the discovery
  step 'enumerate-files'`); the viewer renders it as a story
  column on the propagation table, and `report.md` renders it as
  a `## Propagation narrative` bullet list above the per-step
  module results, so the propagation table reads as a chain
  story rather than a (from, to, kind) graph.
- New public helper `compute_propagation_edges` exported from
  `src.core.reporting`. Wraps the existing manifest-side edge
  extractor so external tooling and the report writer can
  consume the same canonical edge list — including the
  `narrative` field — without reaching into a private name.
- `summarise_run_state` accepts a new `scenario_objective` kwarg
  (capped at 1000 chars to bound prompt budget; whitespace-
  normalised to single-line prose). The prompt body and
  artifact metadata header both surface it, so the offline
  copilot's narrative artifact leads with the chain story.
  `_RUN_SUMMARY_HEADER_KEYS` extended with `scenario_objective`
  so the YAML frontmatter contract stays schema-stable.
- Flagship `enterprise_intrusion_chain` step names rewritten as
  defender-facing chain narrative beats (e.g.
  `Loader execution on victim host` →
  `Encoded PowerShell loader executes on finance-analyst host`;
  `Simulate ransomware encryption-impact` →
  `Ransomware encrypts staged-data fileshare`). Step IDs and
  propagation matrix unchanged — only narrative-quality fields
  move. Scenario `objective:` rewritten as a multi-paragraph
  chain summary that explicitly calls out the simulate-only
  contract.
- FIN7 scenario step names tightened from terse labels
  (`Initial Access`, `Loader Execution`, `C2 Beacon`) to
  chain-narrative phrasing
  (`Spearphishing attachment delivered to finance user`, etc.);
  FIN7 `objective:` rewritten as a multi-line literal block
  describing the chain and calling out the
  `network_touch: false` simulate-only contract.
- `apt29_credential_access` and `healthcare_ransomware` step
  names harmonised with the flagship + FIN7 voice — the
  redundant `Simulate` / `simulation` prefix / suffix dropped
  on every step that previously carried it (PR #126). After
  this change every shipped *standard* scenario reads with
  consistent voice; the simulate-only contract is asserted at
  YAML / runtime level only, not redundantly inside step
  titles.
- **Timeline severity column** (PR #127). The static dashboard's
  scenario timeline now carries a per-step severity badge
  inline so a SOC analyst scanning the timeline top-to-bottom
  sees the chain's risk arc (low → medium → high → critical)
  without cross-referencing the risk-summary card. Steps that
  didn't reach the risk scorer (blocked / errored before
  scoring) render an em-dash, not a fake `unknown` badge.
- **Risk rationale `matters_because` line** (PR #129). The
  rationale list now carries a defender-facing
  `matters_because=<short text>` entry alongside
  `tactic_base=<tactic>`. Phrased in chain-position language
  (`destructive endgame`, `data leaves perimeter`,
  `enables lateral expansion`) so a reader without MITRE
  ATT&CK fluency understands why a step's score landed where
  it did. Both the standard-module path AND the tactic_pack
  legacy path emit the line; out-of-tree modules with no
  documented tactic get no synthesised reason. Surfaces in
  the dashboard "Why" column (PR #114), CLI risk-summary
  "Why" column (PR #116), and `report.md` per-module section
  (PR #131).
- **`report.md` "Why" line** (PR #131). The markdown report's
  per-module section now renders the same defender-facing
  rationale the dashboard's "Why" column shows. Closes the
  surface-consistency gap left after PR #129; legacy callers
  that don't pass a rationale list still produce a clean
  report (line dropped entirely when rationale is empty).

### Changed

- `LegacyWrappedModule` now emits a properly-shaped detection hint
  with an explicitly-labeled `legacy_wrapped/bluefire` logsource +
  `event.module: <name>` selection + `needs_operator_review: True`
  marker, instead of the previous hint of just
  `{"mitre_technique": "T0000"}` which silently fell back to the
  default `process_creation/windows` logsource and mis-labeled
  every wrapped legacy module's Sigma / YARA-L draft as a Windows
  process-creation rule. Generated rules from this adapter now
  surface as "needs operator review" rather than masquerading as
  Sysmon-shaped detections.
- Manifest schema extended additively (no schema_version bump):
  `manifest.run.scenario_objective` (string, default empty);
  each entry of `manifest.propagation_edges` gains
  `from_module` and `narrative`. Legacy consumers reading
  existing keys are unaffected.

### Tests

- New `tests/test_logsource_coverage_invariant.py` (+32): runs
  every registered runtime module with minimal valid params and
  asserts the resulting detection hint includes a non-empty
  `logsource` block (with both `category` and `product` keys).
  Catches future regressions where a new module ships without
  setting logsource — the Sigma / YARA-L generators would
  otherwise silently default to `process_creation/windows`,
  mis-labeling the technique. Modules that intentionally emit no
  hints (e.g. `legacy_capability_summary`) are tracked in an
  exemption set and pinned to actually emit empty hints, so a
  future change there also surfaces.
- Loop F narrative-quality regression tests:
  - `test_every_step_has_a_narrative_name` (flagship + every
    shipped scenario): every step's `name` is non-empty,
    distinct from `step_id`, ≥12 chars, contains a space.
  - `test_scenario_objective_reads_as_story_not_label` (flagship):
    objective is non-empty, ≥200 chars, mentions `simulate` /
    `network_touch` so the safe-by-default contract is visible.
  - Manifest tests for `run.scenario_objective` plumbing,
    propagation edge `from_module` resolution, and narrative
    rendering across all three propagation kinds (with the
    missing-upstream fallback to `"upstream"` placeholder).
  - Viewer tests for objective rendering (paragraph-aware,
    HTML-escaped against script injection), propagation
    narrative column, empty-state handling.
  - Markdown report tests pinning section order (`title →
    objective → coverage → propagation → modules`) and
    paragraph normalisation.
  - Offline copilot tests pinning the `objective:` line in the
    rendered narrative + YAML header, and the
    pathologically-long-objective truncation contract.

## [3.0.0-rc1] - 2026-05-07

First release-candidate of the rebuilt local-first adversary-
emulation baseline. Major-version bump from `v2.8.0` reflects
that the artifact contract, module registry, AI layer, and
safety model have all been re-architected since the prior
release lineage; existing `v2.x` integrations should treat this
as a breaking change and re-validate against the new module
registry and manifest schema.

This is a **release candidate**: the maintainer may publish
`-rc2`, `-rc3`, etc. in response to operator feedback before
cutting the bare `v3.0.0` tag.

Headline story (full per-PR history lives in
[`docs/reports/next_roadmap.md`](docs/reports/next_roadmap.md)):

### Added

- **Local report viewer.** Every run now writes
  `output/<run_id>/manifest.json` (machine-readable index of
  every artifact) and `output/<run_id>/index.html` (a static,
  fully self-contained dashboard — no JavaScript, no external
  assets, no network calls). Viewer renders the scenario
  timeline, propagation graph, ATT&CK coverage, telemetry
  counts, detection drafts, risk summary, and AI provider
  attribution.
- **CLI commands for runs.** `list-runs`, `latest-run`,
  `show-run`, `build-report-view`, `build-output-index`, and
  `validate-run` round out the local-only workflow. None starts
  a server or auto-opens a browser.
- **Top-level run index aggregator.** A static `output/index.html`
  page lists every run newest-first with quick links into each
  run's viewer / manifest / report / risk summary. Same
  self-contained constraints as the per-run viewer (no JS, no
  external assets, no network). The orchestrator refreshes the
  aggregator after every run; `list-runs` / `latest-run`
  surface a `file://` link to it when present.
- **Pure-CSS mini-charts in the run viewer.** Telemetry counts
  by type and by module render as deterministic horizontal bar
  charts (alphabetical key order, widths clamped to 1–100%);
  the KPI grid gains a "Module status" card with tier-coloured
  bars for success / blocked / error / skipped step counts.
  Still pure HTML + inline CSS — no JavaScript, no SVG, no
  external assets.
- **Provider-agnostic AI layer.** `template` (offline default),
  `openai_compatible`, `openai`, `anthropic`, `gemini`, `grok`,
  `ollama`, `llama.cpp`, and `lm-studio` all route through a
  shared `ProviderFactory`. Anthropic and Gemini have
  vendor-specific adapters; the rest use the shared
  OpenAI-compatible HTTP backend. Default is offline /
  template — no API keys required.
- **Step-to-step propagation.** Four consumer pairs are
  demonstrated end-to-end in `enterprise_intrusion_chain`:
  `discovery → credential_access`,
  `credential_access → lateral_movement` (source axis),
  `collection → exfiltration`, and `collection → impact`.
- **Cross-cutting simple-mode presets.** `local_safe`,
  `lab_legacy_enabled`, `ai_enabled`, `ai_disabled`, and
  `strict_local` (loopback-only safety gates).

### Changed

- `--output-json` now produces JSON-only stdout so the README
  quickstart command pipes cleanly into `jq`. Advisory rich
  output routes to stderr.
- README quickstart is now a four-step end-to-end walkthrough
  (clone+install / run / inspect / open) with platform
  variants for `open` / `xdg-open` / `start`.
- Static viewer renders risk summary above the scenario
  timeline; per-module severity badges use the same colour
  palette as the status badges; timeline carries a `notes`
  column for non-success rows.
- `find_run_dir` and `validate_run_bundle` reject path-shaped
  run ids and out-of-bundle hrefs respectively, so neither
  command can read or write outside the configured output
  root.

### Security

- Default `dry_run: true` enforced by registry-wide tests
  (`tests/test_module_safety.py`). No module invokes
  `subprocess` / `socket` / `requests` / `urllib` while
  `dry_run` is on.
- No SIEM exporters or remote observability anywhere on the
  active path. Legacy `telemetry.sinks` config entries naming
  removed remote types are warn-and-ignored at load time.
- Provider calls require explicit `modules.ai.enabled: true`
  plus an operator-supplied endpoint (and, for vendor-specific
  backends, a credential resolved from an environment variable).
- AI keys are read from environment variables only; never
  bundled, never written to disk.

### Tests

- Cross-adapter parity audit across the seven `legacy_*`
  modules (77 parametrised tests) plus per-capability depth
  tests for `legacy_protocol_research` and
  `legacy_stealth_research`.
- 10-test enterprise-chain quality invariant suite (unique
  step ids, every step in dry-mode, forward-reference detection
  on propagation slots, all four pairs demonstrated, declared
  ATT&CK coverage matches runtime emitted coverage).
- 18-test demo-bundle validator suite (no broken viewer links,
  no external schemes, no absolute paths, complete artifact
  set on both flagship scenarios).
- 10-test quickstart smoke harness exercising the full README
  end-to-end via subprocess.
- Final baseline at the rc1 cut: **1525 passed, 5 skipped, 0
  failed** (~98-110s wallclock).

### Pre-rc1 polish fixes

Five focused PRs landed between the original rc1 cut and the
current rc1 baseline, each surfaced by a fresh-clone Windows
smoke run and pinned by tests so they cannot regress:

- **YARA-L `meta.run_id` correlation parity** (PR #89). The
  detection engine wrote real run ids into Sigma rules but
  hardcoded `run_id = "manual"` in YARA-L. A defender
  correlating Sigma <-> YARA-L drafts on `run_id` could not.
  Fixed: `generate_yara_l` now accepts a keyword-only `run_id`
  and the engine threads the real value through.
- **SPL upgrade from metadata echo to real draft** (PR #89).
  The previous renderer emitted `| makeresults | eval ...`
  only — round-tripped run metadata, never touched any data
  source. New shape maps the Sigma `logsource` block onto
  common Splunk sourcetypes (`WinEventLog:Security`, `Sysmon`,
  `linux_audit`, `stream:dns`, etc.), surfaces the Sigma
  `selection` clause as `where` filters, attributes the search
  to the run via `eval`, aggregates with `stats`, and carries
  a leading multi-line backtick `DRAFT detection search`
  comment header so the dashboard cannot oversell maturity.
  Honest README framing in the new "Detection draft maturity"
  section spells out: Sigma most mature, YARA-L medium, SPL
  draft / starter.
- **Cross-platform-safe filenames** (PR #94). The orchestrator
  builds module-result keys as `f"{module}:{step_id}"` to
  disambiguate steps that reuse the same module. That colon
  flowed straight into the detection-artifact filename. On
  NTFS, Windows interprets `:` as the Alternate Data Stream
  separator; the visible filename truncated and the rule body
  was silently lost into an ADS, leaving 0-byte detection
  files behind. Fixed: a `_safe_filename_component` helper
  replaces unsafe characters (`: * ? " < > | / \`) with `__`;
  the manifest / coverage records still carry the original
  colon-separated key.
- **Windows CLI mojibake + `file://` URL on its own line**
  (PR #91). Em-dash (U+2014) in user-facing CLI strings
  rendered as `?` on Windows non-UTF-8 terminals. `file://`
  viewer URLs printed inline could be wrapped by rich's word
  wrap, breaking copy-paste. Fixed: every em-dash in
  `src/core/cli.py` replaced with ASCII (source-level invariant
  pinned by test); URLs now print on a standalone line via
  `console.print(uri, no_wrap=True, overflow="ignore")`.
- **README `.env` quickstart drift** (PR #92). The prior
  `cp .env.example .env` step in the canonical quickstart was
  misleading — the default offline / template AI flow does not
  need `.env` at all. Moved out of the canonical block; framed
  as "only needed when enabling a remote AI provider" in a
  follow-up paragraph that points to USAGE_GUIDELINES.
- **Offline TemplateProvider artifact quality** (PR #93). The
  template provider previously returned a generic 5-line stub
  for every prompt. New behaviour parses the orchestrator's
  `[run summary]` block out of the prompt and renders an
  intent-aware artifact: SOC narrative for `narrate` (with
  step-by-step timeline replay, blocked-step callouts,
  run-specific next-validation paths under `output/<run_id>/`);
  detection-strategy summary for `suggest_detections`
  (per-technique pointers + honest maturity framing);
  scenario YAML skeleton for `plan`. Stays deterministic, no
  network, no API key required.

### Removed

- SIEM exporters and remote observability connectors (Splunk
  HEC, OpenSearch, Elasticsearch, NGSIEM, generic HTTP bulk).
  Legacy `telemetry.sinks` config entries naming removed
  remote types are warn-and-ignored at load time so old configs
  do not crash and do not silently regain network egress.

### Notes for operators upgrading from `v2.8.0`

- The artifact contract has changed. Every run now produces a
  `manifest.json` with a stable schema (see
  `src/core/reporting/manifest.py`) and a self-contained
  `index.html` viewer. Downstream tooling that previously
  parsed `report.json` directly should migrate to reading
  `manifest.json` first.
- The module registry has been re-architected. Standard tactic
  modules are simulate-first and never auto-route through
  legacy code paths; scenarios that need legacy behaviour must
  use an explicit `module: legacy_<tactic>` adapter. The
  `enable_all_lab_capabilities` master toggle, per-pack mode
  flags, and per-capability `lab_confirmation` gates are
  unchanged in shape but the dispatch surface they govern has
  been re-grouped.
- The AI layer is provider-agnostic. The default has remained
  offline / template — no network calls, no API keys required
  for default use. Operator-facing config keys (`modules.ai.*`
  + `ai_providers.<name>.*`) are documented in
  `docs/USAGE_GUIDELINES.md` § AI provider configuration.

## [2.8.0] - 2025-02-23

Last published release of the prior lineage. Predates the
artifact-contract / module-registry / AI-layer rebuild. Kept on
GitHub Releases for historical reference; operators on `v2.8.0`
should treat `v3.0.0-rc1` as a breaking-change upgrade and
re-validate against the new manifest / viewer contract.

## [1.0.0] - 2024-03-20

Pre-`v2.8.0` historical entry. Initial public release of the
earlier lineage. Module framework, scenario runtime, local
telemetry, ATT&CK-mapped detection drafts, purple-team reports,
and gated legacy capability packs. Predates the `v2.8.0`
published release and the `v3.0.0-rc1` rebuild; kept here for
context only.

## [0.1.0] - 2024-03-01

Pre-`v2.8.0` historical entry. Initial development release.
